use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;
use log;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::{interval, Duration};

use crate::node::{Node, ID_LEN, digest};
use crate::storage::ForgetfulStorage;
use crate::protocol::KademliaProtocol;
use crate::auth_handler::SignatureVerifierHandler;

const STATUS_LIST_KEY: &str = "did:iiot:status-list";

/// High-level server Kademlia — corrisponde a `Server` / `network.py` in Python
pub struct Server {
    pub ksize: usize,
    pub alpha: usize,
    pub storage: Arc<ForgetfulStorage>,
    pub node: Node,
    pub protocol: Option<Arc<Mutex<KademliaProtocol>>>,
    signature_handler: Arc<dyn SignatureVerifierHandler>,
}

impl Server {
    pub fn new(
        signature_handler: Arc<dyn SignatureVerifierHandler>,
        ksize: usize,
        alpha: usize,
        node_id: Option<[u8; ID_LEN]>,
        storage: Option<Arc<ForgetfulStorage>>,
    ) -> Self {
        let storage = storage.unwrap_or_else(|| Arc::new(ForgetfulStorage::new(-1)));
        let node = node_id
            .map(Node::from_id)
            .unwrap_or_else(Node::random);

        Self {
            ksize,
            alpha,
            storage,
            node,
            protocol: None,
            signature_handler,
        }
    }

    /// Avvia il server in ascolto sulla porta specificata.
    /// Restituisce il task handle che gestisce i pacchetti UDP.
    pub async fn listen(&mut self, port: u16, interface: &str) -> tokio::io::Result<()> {
        let addr = format!("{}:{}", interface, port);
        let socket = UdpSocket::bind(&addr).await?;
        log::info!(
            "Node {} listening on {}",
            hex::encode(self.node.id),
            addr
        );

        let protocol = Arc::new(Mutex::new(KademliaProtocol::new(
            self.node.clone(),
            Arc::clone(&self.storage),
            self.ksize,
            Arc::clone(&self.signature_handler),
        )));
        self.protocol = Some(Arc::clone(&protocol));

        // Spawna il refresh periodico della routing table (ogni ora)
        let protocol_refresh = Arc::clone(&protocol);
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                log::debug!("Refreshing routing table");
                let _ids = protocol_refresh.lock().await.get_refresh_ids();
                // qui in produzione si eseguirebbe NodeSpiderCrawl per ogni id
            }
        });

        // Spawna il loop di ricezione UDP (stub — in produzione si usa msgpack/bincode)
        let socket = Arc::new(socket);
        let protocol_udp = Arc::clone(&protocol);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        log::debug!("Received {} bytes from {}", len, peer);
                        // Deserializzazione e dispatch dell'RPC da implementare
                        // in base al formato di serializzazione scelto (bincode/msgpack)
                        let _ = &buf[..len];
                        let _ = &protocol_udp;
                    }
                    Err(e) => log::error!("UDP recv error: {}", e),
                }
            }
        });

        Ok(())
    }

    /// Bootstrap: contatta nodi noti per entrare nella rete
    pub async fn bootstrap(&self, addrs: Vec<(String, u16)>) -> Vec<Node> {
        let mut nodes = Vec::new();
        for (ip, port) in addrs {
            // In produzione si fa ping UDP e si aspetta la risposta
            log::debug!("Bootstrapping via {}:{}", ip, port);
            // Placeholder — il nodo viene aggiunto solo dopo il ping riuscito
            let fake_id = digest(&format!("{}:{}", ip, port));
            nodes.push(Node::new(fake_id, Some(ip), Some(port)));
        }
        nodes
    }

    // -------------------------------------------------------------------------
    // API pubblica (get / set / update / delete)
    // -------------------------------------------------------------------------

    /// Cerca una chiave nella rete. Restituisce None se non trovata o firma invalida.
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        log::info!("Looking up key {}", key);
        let dkey = digest(key);

        // Controlla prima lo storage locale
        if let Some(value) = self.storage.get(&dkey) {
            if self.verify_signature(key, &value) {
                return Some(value);
            } else {
                return None;
            }
        }

        // Altrimenti cerca nella rete (spider crawl — stub)
        log::debug!("Key not local, searching network...");
        None // da completare con ValueSpiderCrawl
    }

    /// Pubblica una chiave nella rete (con verifica firma)
    pub async fn set(&self, key: &str, value: Vec<u8>) -> bool {
        if self.storage.get(&digest(key)).is_some() {
            log::error!("record {} already exists", key);
            return false;
        }

        if !self.verify_signature(key, &value) {
            log::error!("Invalid signature for key {}", key);
            return false;
        }

        log::info!("Setting '{}' on network", key);
        let dkey = digest(key);
        self.storage.set(dkey, value.clone());
        self.set_digest(dkey, value).await
    }

    /// Aggiorna una chiave esistente (key rotation o status list)
    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> bool {
        let old_value = match self.get(key).await {
            Some(v) => v,
            None => {
                log::error!("record {} does not exist for update", key);
                return false;
            }
        };

        let ok = if key == STATUS_LIST_KEY && auth_signature.is_none() {
            self.signature_handler
                .handle_issuer_node_signature_verification(&value)
                .unwrap_or(false)
        } else {
            let sig = auth_signature.as_deref().unwrap_or(&[]);
            self.signature_handler
                .handle_update_verification(&value, &old_value, sig)
                .unwrap_or(false)
        };

        if !ok {
            log::error!("Unauthenticated update for key {}", key);
            return false;
        }

        let dkey = digest(key);
        self.storage.set(dkey, value.clone());
        self.update_digest(key, dkey, value, auth_signature).await
    }

    /// Elimina una chiave in modo autenticato
    pub async fn delete(&self, key: &str, auth_signature: Vec<u8>, msg: Vec<u8>) -> bool {
        let value = match self.get(key).await {
            Some(v) => v,
            None => {
                log::error!("record {} not found for delete", key);
                return false;
            }
        };

        let ok = self.signature_handler
            .handle_signature_delete_operation(&value, &auth_signature, &msg)
            .unwrap_or(false);

        if !ok {
            log::error!("Invalid signature on delete for key {}", key);
            return false;
        }

        let dkey = digest(key);
        self.storage.delete(&dkey);
        self.delete_digest(dkey, auth_signature, msg).await
    }

    // -------------------------------------------------------------------------
    // Helpers interni per propagazione nella rete
    // -------------------------------------------------------------------------

    async fn set_digest(&self, dkey: [u8; ID_LEN], value: Vec<u8>) -> bool {
        if let Some(proto) = &self.protocol {
            let proto = proto.lock().await;
            let target = Node::from_id(dkey);
            let neighbors = proto.router.find_neighbors(&target, None);
            if neighbors.is_empty() {
                log::warn!("No neighbors for key {}", hex::encode(dkey));
                return false;
            }
            drop(proto);
            // In produzione: call_store su ogni vicino via UDP
            log::info!("Would propagate key {} to {} neighbors", hex::encode(dkey), neighbors.len());
            true
        } else {
            false
        }
    }

    async fn update_digest(
        &self,
        key: &str,
        dkey: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> bool {
        if let Some(proto) = &self.protocol {
            let proto = proto.lock().await;
            let target = Node::from_id(dkey);
            let neighbors = proto.router.find_neighbors(&target, None);
            drop(proto);
            if neighbors.is_empty() {
                return false;
            }
            log::info!("Would propagate update for key {} to {} neighbors", key, neighbors.len());
            true
        } else {
            false
        }
    }

    async fn delete_digest(
        &self,
        dkey: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> bool {
        if let Some(proto) = &self.protocol {
            let proto = proto.lock().await;
            let target = Node::from_id(dkey);
            let neighbors = proto.router.find_neighbors(&target, None);
            drop(proto);
            log::info!("Would propagate delete for key {} to {} neighbors", hex::encode(dkey), neighbors.len());
            !neighbors.is_empty()
        } else {
            false
        }
    }

    /// Graceful shutdown: notifica i vicini della partenza
    pub async fn stop(&self) {
        log::info!("Stopping server, notifying neighbors...");
        if let Some(proto) = &self.protocol {
            let proto = proto.lock().await;
            let neighbors = proto.router.find_neighbors(&self.node, None);
            log::info!("Notifying {} neighbors of departure", neighbors.len());
            // In produzione: call_leave su ogni vicino via UDP
        }
    }

    /// Salva lo stato su file (formato JSON)
    pub async fn save_state(&self, path: &PathBuf) -> std::io::Result<()> {
        if let Some(proto) = &self.protocol {
            let proto = proto.lock().await;
            let neighbors = proto.router.find_neighbors(&self.node, None);
            let addrs: Vec<_> = neighbors
                .iter()
                .filter_map(|n| n.address())
                .collect();
            drop(proto);

            let state = serde_json::json!({
                "ksize": self.ksize,
                "alpha": self.alpha,
                "id": hex::encode(self.node.id),
                "neighbors": addrs
            });
            std::fs::write(path, serde_json::to_string_pretty(&state)?)?;
        }
        Ok(())
    }

    // Helpers per verifica firma in base al tipo di chiave
    fn verify_signature(&self, key: &str, value: &[u8]) -> bool {
        if key == STATUS_LIST_KEY {
            self.signature_handler
                .handle_issuer_node_signature_verification(value)
                .unwrap_or(false)
        } else {
            self.signature_handler
                .handle_signature_verification(value)
                .unwrap_or(false)
        }
    }
}

/// Controlla che il tipo del valore sia valido per la DHT
pub fn check_dht_value_type(value: &[u8]) -> bool {
    !value.is_empty()
}
