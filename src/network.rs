/// Exact translation of network.py (Python class Server)
///
/// High-level view of a node instance. This is the object that should be
/// created to start listening as an active node on the network.
use std::sync::Arc;
use log;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::node::Node;
use crate::storage::{ForgetfulStorage, IStorage};
use crate::utils::{digest, ID_LEN};
use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{NodeSpiderCrawl, ValueSpiderCrawl};
use crate::protocol::KademliaProtocol;

const STATUS_LIST_KEY: &str = "did:iiot:status-list";

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────

pub struct Server {
    pub ksize: usize,
    pub alpha: usize,
    pub storage: Arc<Mutex<ForgetfulStorage>>,
    pub node: Node,
    pub transport: Option<Arc<UdpSocket>>,
    pub protocol: Option<Arc<KademliaProtocol>>,
    pub refresh_loop: Option<tokio::task::JoinHandle<()>>,
    pub save_state_loop: Option<tokio::task::JoinHandle<()>>,
    pub signature_handler: Arc<dyn SignatureVerifierHandler>,
}

impl Server {
    /// Python: Server.__init__
    pub fn new(
        signature_handler: Arc<dyn SignatureVerifierHandler>,
        ksize: usize,
        alpha: usize,
        node_id: Option<[u8; ID_LEN]>,
        storage: Option<Arc<Mutex<ForgetfulStorage>>>,
    ) -> Self {
        let storage = storage.unwrap_or_else(|| Arc::new(Mutex::new(ForgetfulStorage::new(-1))));
        let node = match node_id {
            Some(id) => Node::from_id(id),
            None => {
                // Python: Node(digest(random.getrandbits(255)))
                let random_bytes = {
                    use rand::RngCore;
                    let mut b = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut b);
                    b
                };
                Node::from_id(crate::utils::digest_bytes(&random_bytes))
            }
        };
        Self {
            ksize,
            alpha,
            storage,
            node,
            transport: None,
            protocol: None,
            refresh_loop: None,
            save_state_loop: None,
            signature_handler,
        }
    }

    /// Python: Server.stop()
    pub async fn stop(&mut self) {
        log::info!("Stopping the server and notifying neighbors of node departure.");

        if let Some(proto) = &self.protocol {
            let neighbors = proto.router.lock().await.find_neighbors(&self.node, None);
            log::info!("Notifying {} neighbors of departure.", neighbors.len());
            let mut tasks = vec![];
            for neighbor in neighbors {
                let p = Arc::clone(proto);
                let node_id = self.node.id;
                tasks.push(tokio::spawn(async move {
                    p.call_leave(&neighbor, node_id).await;
                }));
            }
            futures::future::join_all(tasks).await;
        }

        if let Some(refresh) = self.refresh_loop.take() {
            refresh.abort();
        }
        if let Some(save) = self.save_state_loop.take() {
            save.abort();
        }
    }

    /// Python: Server.listen(port, interface='0.0.0.0')
    pub async fn listen(&mut self, port: u16, interface: &str) -> tokio::io::Result<()> {
        let addr = format!("{}:{}", interface, port);
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        log::info!("Node {} listening on {}:{}", self.node.long_id, interface, port);
        self.transport = Some(Arc::clone(&socket));

        let protocol = Arc::new(KademliaProtocol::new(
            self.node.clone(),
            Arc::clone(&self.storage),
            self.ksize,
            Arc::clone(&self.signature_handler),
        ));
        self.protocol = Some(Arc::clone(&protocol));

        // UDP receive loop (dispatch RPC messages)
        let proto_udp = Arc::clone(&protocol);
        let sock = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match sock.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let data = buf[..len].to_vec();
                        let p = Arc::clone(&proto_udp);
                        tokio::spawn(async move {
                            p.handle_datagram(data, peer).await;
                        });
                    }
                    Err(e) => log::error!("UDP recv error: {}", e),
                }
            }
        });

        // Python: self.refresh_table()
        self.refresh_table();
        Ok(())
    }

    /// Python: Server.refresh_table(interval=3600)
    pub fn refresh_table(&mut self) {
        log::debug!("Refreshing routing table");
        if let Some(proto) = &self.protocol {
            let proto = Arc::clone(proto);
            let storage = Arc::clone(&self.storage);
            let ksize = self.ksize;
            let alpha = self.alpha;
            let handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    log::debug!("Refreshing routing table (scheduled)");

                    // Python: for node_id in self.protocol.get_refresh_ids(): NodeSpiderCrawl(...).find()
                    let refresh_ids = proto.get_refresh_ids().await;
                    let mut futs = vec![];
                    for rid in refresh_ids {
                        let rnode = Node::from_id(rid);
                        let neighbors = proto.router.lock().await.find_neighbors(&rnode, None);
                        let spider = NodeSpiderCrawl::new(
                            Arc::clone(&proto),
                            rnode, neighbors, ksize, alpha,
                        );
                        futs.push(spider.find());
                    }
                    futures::future::join_all(futs).await;

                    // Python: republish keys older than 1 hour
                    let older = storage.lock().await.iter_older_than(3600);
                    for (dkey_vec, value) in older {
                        if dkey_vec.len() == ID_LEN {
                            let mut dkey = [0u8; ID_LEN];
                            dkey.copy_from_slice(&dkey_vec);
                            // set_digest equivalent inline
                            let target = Node::from_id(dkey);
                            let neighbors = proto.router.lock().await.find_neighbors(&target, None);
                            if !neighbors.is_empty() {
                                let spider = NodeSpiderCrawl::new(
                                    Arc::clone(&proto),
                                    target, neighbors, ksize, alpha,
                                );
                                let nodes = spider.find().await;
                                for n in nodes {
                                    proto.call_store(&n, dkey, value.clone()).await;
                                }
                            }
                        }
                    }
                }
            });
            self.refresh_loop = Some(handle);
        }
    }

    /// Python: Server.bootstrappable_neighbors()
    pub async fn bootstrappable_neighbors(&self) -> Vec<(String, u16)> {
        if let Some(proto) = &self.protocol {
            let neighbors = proto.router.lock().await.find_neighbors(&self.node, None);
            neighbors.into_iter().filter_map(|n| n.address()).collect()
        } else {
            vec![]
        }
    }

    /// Python: Server.bootstrap(addrs)
    pub async fn bootstrap(&self, addrs: Vec<(String, u16)>) -> Vec<Node> {
        log::debug!("Attempting to bootstrap node with {} initial contacts", addrs.len());
        let mut futs = vec![];
        for addr in addrs {
            futs.push(self.bootstrap_node(addr));
        }
        let gathered: Vec<Option<Node>> = futures::future::join_all(futs).await;
        let nodes: Vec<Node> = gathered.into_iter().flatten().collect();

        if let Some(proto) = &self.protocol {
            let spider = NodeSpiderCrawl::new(
                Arc::clone(proto),
                self.node.clone(), nodes, self.ksize, self.alpha,
            );
            spider.find().await
        } else {
            vec![]
        }
    }

    /// Python: Server.bootstrap_node(addr)
    pub async fn bootstrap_node(&self, addr: (String, u16)) -> Option<Node> {
        if let Some(proto) = &self.protocol {
            let result = proto.call_ping_addr(&addr).await;
            if result.0 {
                let mut id = [0u8; ID_LEN];
                let src = result.1;
                let copy_len = src.len().min(ID_LEN);
                id[..copy_len].copy_from_slice(&src[..copy_len]);
                Some(Node::new(id, Some(addr.0), Some(addr.1)))
            } else {
                None
            }
        } else {
            None
        }
    }

    // ─── Signature dispatch helpers (Python: _handle_type_signature_verification) ───

    fn handle_type_signature_verification(&self, key: &str, value: &[u8]) -> bool {
        if key == STATUS_LIST_KEY {
            let ok = self.signature_handler
                .handle_issuer_node_signature_verification(value)
                .unwrap_or(false);
            if ok { log::info!("[Log] Status List Signature Verified!"); }
            ok
        } else {
            self.signature_handler
                .handle_signature_verification(value)
                .unwrap_or(false)
        }
    }

    fn handle_type_update_verification(
        &self,
        key: &str,
        value: &[u8],
        old_value: &[u8],
        auth_signature: Option<&[u8]>,
    ) -> bool {
        if key == STATUS_LIST_KEY && auth_signature.is_none() {
            let ok = self.signature_handler
                .handle_issuer_node_signature_verification(value)
                .unwrap_or(false);
            if ok { log::info!("Updating Status List (Authenticated)"); }
            ok
        } else {
            log::info!("Updating key-pair");
            self.signature_handler
                .handle_update_verification(value, old_value, auth_signature.unwrap_or(&[]))
                .unwrap_or(false)
        }
    }

    // ─── get_fallback ───────────────────────────────────────────────────────

    /// Python: Server.get_fallback(key)
    pub async fn get_fallback(&self, key: &str) -> Option<Vec<u8>> {
        log::info!("Looking up key {}", key);
        let dkey = digest(key);

        let result_local: Option<Vec<u8>> = {
            let st = self.storage.lock().await;
            let v = st.get(&dkey);
            if let Some(ref val) = v {
                if !self.handle_type_signature_verification(key, val) {
                    return None;
                }
            }
            v
        };

        let proto = self.protocol.as_ref()?;
        let node = Node::from_id(dkey);
        let nearest = proto.router.lock().await.find_neighbors(&node, None);
        if nearest.is_empty() {
            log::warn!("There are no known neighbors to get key {}", key);
            return None;
        }
        let spider = ValueSpiderCrawl::new(
            Arc::clone(proto),
            node, nearest, self.ksize, self.alpha,
        );
        let result = spider.find().await;

        if let Some(ref val) = result {
            if self.handle_type_signature_verification(key, val) {
                // Python: if result_local != result and result_local is not None:
                //             self.storage[dkey] = None
                if let Some(ref local) = result_local {
                    if local != val {
                        log::info!("get_fallback: aggiornato valore corretto per {}", key);
                        self.storage.lock().await.set(dkey.to_vec(), vec![]);
                    }
                }
                return result;
            }
        }
        None
    }

    // ─── get ────────────────────────────────────────────────────────────────

    /// Python: Server.get(key)
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        log::info!("Looking up key {}", key);
        let dkey = digest(key);

        // if this node has it, return it
        {
            let st = self.storage.lock().await;
            if let Some(result) = st.get(&dkey) {
                let ok = self.handle_type_signature_verification(key, &result);
                if !ok { return None; }
                return Some(result);
            }
        }

        let proto = self.protocol.as_ref()?;
        let node = Node::from_id(dkey);
        let nearest = proto.router.lock().await.find_neighbors(&node, None);
        if nearest.is_empty() {
            log::warn!("There are no known neighbors to get key {}", key);
            return None;
        }
        let spider = ValueSpiderCrawl::new(
            Arc::clone(proto),
            node, nearest, self.ksize, self.alpha,
        );
        let result = spider.find().await;
        if let Some(ref val) = result {
            if self.handle_type_signature_verification(key, val) {
                return result;
            }
        }
        None
    }

    // ─── set ────────────────────────────────────────────────────────────────

    /// Python: Server.set(key, value)
    pub async fn set(&self, key: &str, value: Vec<u8>) -> Option<bool> {
        // Python: result = await self.get(key); if result: return None
        let existing = self.get(key).await;
        if existing.is_some() {
            log::error!("record {} already exists", key);
            return None;
        }

        if !self.handle_type_signature_verification(key, &value) {
            log::error!("Invalid Signature");
            return None;
        }
        log::debug!("SIGNATURE VERIFIED");

        log::info!("setting '{}' on network", key);
        let dkey = digest(key);
        Some(self.set_digest(dkey, value).await)
    }

    // ─── update ─────────────────────────────────────────────────────────────

    /// Python: Server.update(key, value, auth_signature)
    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> Option<bool> {
        let old_value = self.get(key).await;
        if old_value.is_none() {
            log::error!("record {} does not exist", key);
            return None;
        }
        let old_value = old_value.unwrap();

        let ok = self.handle_type_update_verification(
            key,
            &value,
            &old_value,
            auth_signature.as_deref(),
        );
        if !ok {
            log::info!("Unauthenticated update operation");
            return None;
        }
        log::info!("AUTHENTICATED UPDATE!");

        let dkey = digest(key);
        Some(self.update_digest(key, dkey, value, auth_signature).await)
    }

    // ─── delete ─────────────────────────────────────────────────────────────

    /// Python: Server.delete(key, auth_signature, msg)
    pub async fn delete(&self, key: &str, auth_signature: Vec<u8>, msg: Vec<u8>) -> Option<bool> {
        let value = self.get(key).await;
        if value.is_none() {
            log::error!("record {} not exists", key);
            return None;
        }
        let value = value.unwrap();

        let ok = self.signature_handler
            .handle_signature_delete_operation(&value, &auth_signature, &msg)
            .unwrap_or(false);
        if !ok {
            log::error!("Invalid Signature");
            return None;
        }
        log::debug!("Delete operation Verified (network.rs)");

        let dkey = digest(key);
        Some(self.delete_digest(dkey, auth_signature, msg).await)
    }

    // ─── delete_digest ───────────────────────────────────────────────────────

    /// Python: Server.delete_digest(dkey, auth_signature, delete_msg)
    pub async fn delete_digest(
        &self,
        dkey: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> bool {
        let proto = match &self.protocol { Some(p) => p, None => return false };
        let node = Node::from_id(dkey);
        let nearest = proto.router.lock().await.find_neighbors(&node, None);
        if nearest.is_empty() {
            log::warn!("There are no known neighbors to delete key {}", hex::encode(dkey));
            return false;
        }
        let spider = NodeSpiderCrawl::new(
            Arc::clone(proto),
            node, nearest, self.ksize, self.alpha,
        );
        let nodes = spider.find().await;
        log::info!("deleting '{}' on {} nodes", hex::encode(dkey), nodes.len());

        self.storage.lock().await.delete(&dkey);
        let mut futs = vec![];
        for n in &nodes {
            let p = Arc::clone(proto);
            let n = n.clone();
            let sig = auth_signature.clone();
            let msg = delete_msg.clone();
            futs.push(async move { p.call_delete(&n, dkey, sig, msg).await });
        }
        let results: Vec<bool> = futures::future::join_all(futs).await;
        results.iter().any(|&r| r)
    }

    // ─── set_digest ──────────────────────────────────────────────────────────

    /// Python: Server.set_digest(dkey, value)
    pub async fn set_digest(&self, dkey: [u8; ID_LEN], value: Vec<u8>) -> bool {
        let proto = match &self.protocol { Some(p) => p, None => return false };
        let node = Node::from_id(dkey);
        let nearest = proto.router.lock().await.find_neighbors(&node, None);
        if nearest.is_empty() {
            log::warn!("There are no known neighbors to set key {}", hex::encode(dkey));
            return false;
        }
        let spider = NodeSpiderCrawl::new(
            Arc::clone(proto),
            node.clone(), nearest, self.ksize, self.alpha,
        );
        let nodes = spider.find().await;
        log::info!("setting '{}' on {} nodes", hex::encode(dkey), nodes.len());

        // Python: biggest = max([n.distance_to(node) for n in nodes])
        //         if self.node.distance_to(node) < biggest: self.storage[dkey] = value
        if let Some(biggest) = nodes.iter().map(|n| n.distance_to(&node)).max() {
            if self.node.distance_to(&node) < biggest {
                self.storage.lock().await.set(dkey.to_vec(), value.clone());
            }
        }

        let mut futs = vec![];
        for n in &nodes {
            let p = Arc::clone(proto);
            let n = n.clone();
            let v = value.clone();
            futs.push(async move { p.call_store(&n, dkey, v).await });
        }
        let results: Vec<bool> = futures::future::join_all(futs).await;
        results.iter().any(|&r| r)
    }

    // ─── update_digest ───────────────────────────────────────────────────────

    /// Python: Server.update_digest(key, dkey, value, auth_signature)
    pub async fn update_digest(
        &self,
        key: &str,
        dkey: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> bool {
        let proto = match &self.protocol { Some(p) => p, None => return false };
        let node = Node::from_id(dkey);
        let nearest = proto.router.lock().await.find_neighbors(&node, None);
        log::debug!("Nodi nearest: {:?}", nearest.len());
        if nearest.is_empty() {
            log::debug!("[Debug] There are no neighbor nodes which contain {}", key);
            return false;
        }
        let spider = NodeSpiderCrawl::new(
            Arc::clone(proto),
            node.clone(), nearest, self.ksize, self.alpha,
        );
        let nodes = spider.find().await;

        if let Some(biggest) = nodes.iter().map(|n| n.distance_to(&node)).max() {
            if self.node.distance_to(&node) < biggest {
                self.storage.lock().await.set(dkey.to_vec(), value.clone());
            }
        }

        let mut futs: Vec<_> = vec![];
        for n in &nodes {
            let p = Arc::clone(proto);
            let n = n.clone();
            let v = value.clone();
            let d = dkey;
            if key == STATUS_LIST_KEY {
                futs.push(Box::pin(async move {
                    p.call_status_list_update(&n, d, v).await
                }) as std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>);
            } else {
                let sig = auth_signature.clone().unwrap_or_default();
                futs.push(Box::pin(async move {
                    p.call_update(&n, d, v, sig).await
                }));
            }
        }
        let results: Vec<bool> = futures::future::join_all(futs).await;
        results.iter().any(|&r| r)
    }

    // ─── save_state / load_state ─────────────────────────────────────────────

    /// Python: Server.save_state(fname)
    pub async fn save_state(&self, fname: &str) {
        log::info!("Saving state to {}", fname);
        let neighbors = self.bootstrappable_neighbors().await;
        if neighbors.is_empty() {
            log::warn!("No known neighbors, so not writing to cache.");
            return;
        }
        let data = serde_json::json!({
            "ksize": self.ksize,
            "alpha": self.alpha,
            "id": hex::encode(self.node.id),
            "neighbors": neighbors,
        });
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            let _ = std::fs::write(fname, json);
        }
    }

    /// Python: Server.save_state_regularly(fname, frequency=600)
    pub fn save_state_regularly(&mut self, fname: String, frequency_secs: u64) {
        let node = self.node.clone();
        let ksize = self.ksize;
        let alpha = self.alpha;
        if let Some(proto) = &self.protocol {
            let proto = Arc::clone(proto);
            let handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(frequency_secs)).await;
                    log::info!("Saving state to {}", fname);
                    let neighbors: Vec<_> = proto.router.lock().await
                        .find_neighbors(&node, None)
                        .into_iter()
                        .filter_map(|n| n.address())
                        .collect();
                    if !neighbors.is_empty() {
                        let data = serde_json::json!({
                            "ksize": ksize,
                            "alpha": alpha,
                            "id": hex::encode(node.id),
                            "neighbors": neighbors,
                        });
                        if let Ok(json) = serde_json::to_string_pretty(&data) {
                            let _ = std::fs::write(&fname, json);
                        }
                    }
                }
            });
            self.save_state_loop = Some(handle);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// check_dht_value_type — Python equivalent
// ─────────────────────────────────────────────────────────────────────────────

/// Python: check_dht_value_type(value)
/// In Rust, DHT values are always bytes (Vec<u8>), so this is always true
/// unless empty. We keep it for API parity.
pub fn check_dht_value_type(value: &[u8]) -> bool {
    !value.is_empty()
}
