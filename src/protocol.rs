use std::sync::Arc;
use log;
use tokio::sync::Mutex;
use async_trait::async_trait;

use crate::node::Node;
use crate::utils::{ID_LEN, digest};
use crate::routing::RoutingTable;
use crate::storage::{ForgetfulStorage, IStorage};
use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{SpiderProtocol, RawResponse, FindPayload};

const STATUS_LIST_KEY: &str = "did:iiot:status-list";

/// Messaggio RPC in entrata/uscita (semplificato — in produzione si usa UDP + msgpack/bincode)
#[derive(Debug, Clone)]
pub enum RpcMessage {
    Ping { sender_id: [u8; ID_LEN], sender_addr: (String, u16) },
    Store { sender_id: [u8; ID_LEN], sender_addr: (String, u16), key: [u8; ID_LEN], value: Vec<u8> },
    Update { sender_id: [u8; ID_LEN], sender_addr: (String, u16), key: [u8; ID_LEN], value: Vec<u8>, auth_signature: Vec<u8> },
    UpdateStatusList { sender_id: [u8; ID_LEN], sender_addr: (String, u16), key: [u8; ID_LEN], value: Vec<u8> },
    Delete { sender_id: [u8; ID_LEN], sender_addr: (String, u16), key: [u8; ID_LEN], auth_signature: Vec<u8>, delete_msg: Vec<u8> },
    FindNode { sender_id: [u8; ID_LEN], sender_addr: (String, u16), key: [u8; ID_LEN] },
    FindValue { sender_id: [u8; ID_LEN], sender_addr: (String, u16), key: [u8; ID_LEN] },
    Leave { sender_id: [u8; ID_LEN], sender_addr: (String, u16) },
}

#[derive(Debug, Clone)]
pub enum RpcResponse {
    Pong([u8; ID_LEN]),
    StoreResult(bool),
    UpdateResult(bool),
    DeleteResult(bool),
    Nodes(Vec<Node>),
    Value(Vec<u8>),
    LeaveAck,
}

/// Risultato di find_value: nodi vicini o valore trovato
#[derive(Debug)]
pub enum FindValueResult {
    Nodes(Vec<Node>),
    Value(Vec<u8>),
}

pub struct KademliaProtocol {
    pub router: Arc<Mutex<RoutingTable>>,
    pub storage: Arc<Mutex<ForgetfulStorage>>,
    pub source_node: Node,
    pub signature_handler: Arc<dyn SignatureVerifierHandler>,
}

impl KademliaProtocol {
    pub fn new(
        source_node: Node,
        storage: Arc<Mutex<ForgetfulStorage>>,
        ksize: usize,
        signature_handler: Arc<dyn SignatureVerifierHandler>,
    ) -> Self {
        let router = RoutingTable::new(source_node.clone(), ksize);
        Self { router: Arc::new(Mutex::new(router)), storage, source_node, signature_handler }
    }

    // -------------------------------------------------------------------------
    // RPC handlers (equivalente ai rpc_* in Python)
    // -------------------------------------------------------------------------

    pub fn rpc_stun(&self, sender_addr: (String, u16)) -> (String, u16) {
        sender_addr
    }

    pub async fn rpc_ping(&mut self, sender_id: [u8; ID_LEN], sender_addr: (String, u16)) -> [u8; ID_LEN] {
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.source_node.id
    }

    pub async fn rpc_store(
        &mut self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        if self.storage.lock().await.get(&key).is_some() {
            log::error!("record {:?} already exists", hex::encode(key));
            return false;
        }

        let is_valid = self.verify_for_key(&key, &value, VerifyMode::Store);
        if !is_valid {
            log::error!("Invalid Signature on store");
            return false;
        }

        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        log::debug!("storing key={}", hex::encode(key));
        self.storage.lock().await.set(key.to_vec(), value);
        true
    }

    pub async fn rpc_update(
        &mut self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> bool {
        let old_value = match self.storage.lock().await.get(&key) {
            Some(v) => v,
            None => {
                log::error!("Record {:?} does not exist for update", hex::encode(key));
                return false;
            }
        };

        let ok = self.signature_handler
            .handle_update_verification(&value, &old_value, &auth_signature)
            .unwrap_or(false);

        if !ok {
            log::error!("Unauthenticated DID Document Update");
            return false;
        }

        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.storage.lock().await.set(key.to_vec(), value);
        true
    }

    pub async fn rpc_update_status_list(
        &mut self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        if self.storage.lock().await.get(&key).is_none() {
            log::error!("Record {:?} does not exist for status list update", hex::encode(key));
            return false;
        }

        let ok = self.signature_handler
            .handle_issuer_node_signature_verification(&value)
            .unwrap_or(false);

        if !ok {
            log::error!("Unauthenticated Status List Update");
            return false;
        }

        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.storage.lock().await.set(key.to_vec(), value);
        true
    }

    pub async fn rpc_delete(
        &mut self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> bool {
        let value = match self.storage.lock().await.get(&key) {
            Some(v) => v,
            None => {
                log::error!("record {:?} not found for delete", hex::encode(key));
                return false;
            }
        };

        let ok = self.signature_handler
            .handle_signature_delete_operation(&value, &auth_signature, &delete_msg)
            .unwrap_or(false);

        if !ok {
            log::error!("Invalid Signature on delete");
            return false;
        }

        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.storage.lock().await.delete(&key);
        true
    }

    pub async fn rpc_find_node(
        &mut self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
    ) -> Vec<Node> {
        let source = Node::new(sender_id, Some(sender_addr.0.clone()), Some(sender_addr.1));
        self.welcome_if_new(source.clone()).await;
        let target = Node::from_id(key);
        self.router.lock().await.find_neighbors(&target, Some(&source))
    }

    pub async fn rpc_find_value(
        &mut self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
    ) -> FindValueResult {
        let source = Node::new(sender_id, Some(sender_addr.0.clone()), Some(sender_addr.1));
        self.welcome_if_new(source.clone()).await;
        let value = self.storage.lock().await.get(&key);
        match value {
            Some(v) => FindValueResult::Value(v),
            None => {
                let neighbors = self.rpc_find_node(sender_id, sender_addr, key).await;
                FindValueResult::Nodes(neighbors)
            }
        }
    }

    pub async fn rpc_leave(
        &mut self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
    ) -> bool {
        log::info!("Node {} is leaving the network.", hex::encode(sender_id));
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.router.lock().await.remove_contact(&source);
        true
    }

    // -------------------------------------------------------------------------
    // Helpers interni
    // -------------------------------------------------------------------------

    fn verify_for_key(&self, key: &[u8; ID_LEN], value: &[u8], _mode: VerifyMode) -> bool {
        let status_list_key = digest(STATUS_LIST_KEY);
        if *key == status_list_key {
            self.signature_handler
                .handle_issuer_node_signature_verification(value)
                .unwrap_or(false)
        } else {
            self.signature_handler
                .handle_signature_verification(value)
                .unwrap_or(false)
        }
    }

    /// Se il nodo è nuovo, invia le chiavi di cui dovrebbe essere responsabile
    /// e aggiungilo alla routing table (sezione 2.5 del paper Kademlia).
    pub async fn welcome_if_new(&mut self, node: Node) {
        let is_new = !self.router.lock().await.is_new_node(&node);
        if !is_new {
            return;
        }
        log::info!("New node discovered: {}", node);

        let all_entries = self.storage.lock().await.iter_all();
        let node_clone = node.clone();
        let mut router = self.router.lock().await;
        let _to_store: Vec<_> = all_entries
            .into_iter()
            .filter(|(key_vec, _)| {
                let mut key = [0u8; ID_LEN];
                if key_vec.len() == ID_LEN {
                    key.copy_from_slice(key_vec);
                    let key_node = Node::from_id(key);
                    let neighbors = router.find_neighbors(&key_node, None);
                    if let Some(last) = neighbors.last() {
                        let last_dist = last.distance_to(&key_node);
                        let new_dist = node_clone.distance_to(&key_node);
                        if new_dist < last_dist {
                            if let Some(first) = neighbors.first() {
                                let first_dist = first.distance_to(&key_node);
                                let self_dist = self.source_node.distance_to(&key_node);
                                return self_dist < first_dist;
                            }
                        }
                    }
                    neighbors.is_empty()
                } else {
                    false
                }
            })
            .collect();

        // In un'implementazione con transport UDP si invierebbe call_store qui.
        // Lo scheduling asincrono è delegato al layer Server.

        router.add_contact(node);
    }

    /// IDs dei bucket "lonely" da rinfrescare
    pub async fn get_refresh_ids(&self) -> Vec<[u8; ID_LEN]> {
        use rand::Rng;
        self.router.lock().await
            .lonely_buckets()
            .iter()
            .map(|_b| {
                let mut id = [0u8; ID_LEN];
                rand::thread_rng().fill(&mut id);
                id
            })
            .collect()
    }

    // ─── UDP RPC call methods (async, for calling other nodes) ───

    /// Handle incoming UDP datagram (parse and dispatch to RPC handler)
    pub async fn handle_datagram(&self, _data: Vec<u8>, _peer: std::net::SocketAddr) {
        // TODO: Deserialize message from bincode/msgpack, dispatch to appropriate RPC handler
        log::debug!("handle_datagram not yet implemented");
    }

    /// Call ping on a specific address
    pub async fn call_ping_addr(&self, _addr: &(String, u16)) -> (bool, Vec<u8>) {
        // TODO: Send UDP ping request, get response
        (false, vec![])
    }

    /// Call store on a peer
    pub async fn call_store(&self, _peer: &Node, _key: [u8; ID_LEN], _value: Vec<u8>) -> bool {
        // TODO: Send UDP store request
        false
    }

    /// Call update on a peer
    pub async fn call_update(&self, _peer: &Node, _key: [u8; ID_LEN], _value: Vec<u8>, _auth_signature: Vec<u8>) -> bool {
        // TODO: Send UDP update request
        false
    }

    /// Call status list update on a peer
    pub async fn call_status_list_update(&self, _peer: &Node, _key: [u8; ID_LEN], _value: Vec<u8>) -> bool {
        // TODO: Send UDP status list update request
        false
    }

    /// Call delete on a peer
    pub async fn call_delete(&self, _peer: &Node, _key: [u8; ID_LEN], _auth_signature: Vec<u8>, _delete_msg: Vec<u8>) -> bool {
        // TODO: Send UDP delete request
        false
    }

    /// Call leave to notify peer we're leaving
    pub async fn call_leave(&self, _peer: &Node, _node_id: [u8; ID_LEN]) {
        // TODO: Send UDP leave request
    }
}

enum VerifyMode { Store }

// ─────────────────────────────────────────────────────────────────────────────
// SpiderProtocol implementation
// ─────────────────────────────────────────────────────────────────────────────

#[async_trait]
impl SpiderProtocol for KademliaProtocol {
    async fn call_find_node(&self, _peer: &Node, _target: &Node) -> RawResponse {
        // TODO: Implement actual UDP call
        RawResponse(false, FindPayload::Empty)
    }

    async fn call_find_value(&self, _peer: &Node, _target: &Node) -> RawResponse {
        // TODO: Implement actual UDP call
        RawResponse(false, FindPayload::Empty)
    }

    async fn call_store(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool {
        // Delegate to the RPC call
        Self::call_store(self, peer, key, value).await
    }
}
