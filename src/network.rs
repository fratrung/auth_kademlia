/// High-level Kademlia node (Server).
///
/// `Server` is the public API surface of the DHT. It manages the UDP socket,
/// the protocol instance, background refresh/save tasks, and exposes the
/// `get`, `set`, `update`, and `delete` operations used by application code.
use std::sync::Arc;
use std::time::Duration;

use log;
use tokio::net::UdpSocket;

use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{NodeSpiderCrawl, ValueSpiderCrawl};
use crate::node::Node;
use crate::protocol::KademliaProtocol;
use crate::signature_cache::SignatureCache;
use crate::storage::{ForgetfulStorage, IStorage};
use crate::utils::{digest, digest_bytes, ID_LEN};

const STATUS_LIST_KEY: &str = "did:iiot:status-list";

pub struct Server {
    pub ksize: usize,
    pub alpha: usize,
    pub storage: Arc<ForgetfulStorage>,
    pub node: Node,
    pub protocol: Option<Arc<KademliaProtocol>>,
    refresh_loop: Option<tokio::task::JoinHandle<()>>,
    save_state_loop: Option<tokio::task::JoinHandle<()>>,
    signature_handler: Arc<dyn SignatureVerifierHandler>,
    /// Shared with `KademliaProtocol` so a verification result cached at the
    /// network layer (rpc_store) is immediately reused at the API layer (get/set)
    /// and vice versa. `None` when the cache is disabled via `use_cache: false`.
    sig_cache: Option<Arc<SignatureCache>>,
}

impl Server {
    /// Create a new server instance.
    ///
    /// - `signature_handler` — pluggable signature verification strategy.
    /// - `ksize`             — Kademlia k parameter (bucket size, default 20).
    /// - `alpha`             — concurrency factor (default 3).
    /// - `node_id`           — fixed node ID; pass `None` for a random one.
    /// - `storage`           — custom storage; pass `None` for the default.
    /// - `use_cache`         — enable the signature verification cache (recommended:
    ///                         `true`). Pass `false` to force full Dilithium
    ///                         re-verification on every operation (useful for
    ///                         benchmarking or security auditing).
    pub fn new(
        signature_handler: Arc<dyn SignatureVerifierHandler>,
        ksize: usize,
        alpha: usize,
        node_id: Option<[u8; ID_LEN]>,
        storage: Option<Arc<ForgetfulStorage>>,
        use_cache: bool,
    ) -> Self {
        let storage = storage.unwrap_or_else(|| Arc::new(ForgetfulStorage::new(-1)));

        let node = match node_id {
            Some(id) => Node::from_id(id),
            None => {
                use rand::RngCore;
                let mut b = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut b);
                Node::from_id(digest_bytes(&b))
            }
        };

        let sig_cache = use_cache.then(|| Arc::new(SignatureCache::new(4096)));

        Self {
            ksize,
            alpha,
            storage,
            node,
            protocol: None,
            refresh_loop: None,
            save_state_loop: None,
            signature_handler,
            sig_cache,
        }
    }

    /// Bind to `interface:port` and start the UDP receive loop.
    ///
    /// Each datagram is handled in its own Tokio task. A semaphore caps the
    /// number of tasks in flight: when the limit is reached the datagram is
    /// dropped — UDP-native backpressure that bounds memory under load without
    /// serialising any processing.
    pub async fn listen(&mut self, port: u16, interface: &str) -> tokio::io::Result<()> {
        let addr = format!("{}:{}", interface, port);
        let socket = Arc::new(UdpSocket::bind(&addr).await?);
        log::info!("Node {} listening on {}", self.node.long_id, addr);

        let protocol = Arc::new(KademliaProtocol::new(
            self.node.clone(),
            Arc::clone(&socket),
            Arc::clone(&self.storage),
            self.ksize,
            Arc::clone(&self.signature_handler),
            self.sig_cache.clone(),
        ));
        self.protocol = Some(Arc::clone(&protocol));

        const MAX_INFLIGHT: usize = 1024;
        let inflight = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT));

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let data = buf[..len].to_vec();
                        let proto = Arc::clone(&protocol);
                        match Arc::clone(&inflight).try_acquire_owned() {
                            Ok(permit) => {
                                tokio::spawn(async move {
                                    proto.handle_datagram(data, peer).await;
                                    drop(permit);
                                });
                            }
                            Err(_) => {
                                log::warn!(
                                    "Max in-flight datagrams reached — dropping from {}",
                                    peer
                                );
                            }
                        }
                    }
                    Err(e) => log::error!("UDP recv error: {}", e),
                }
            }
        });

        self.schedule_refresh();
        Ok(())
    }

    /// Gracefully shut down: notify neighbours and cancel background tasks.
    pub async fn stop(&mut self) {
        if let Some(proto) = &self.protocol {
            let neighbors = proto.router.read().await.find_neighbors(&self.node, None);
            log::info!("Notifying {} neighbours of departure", neighbors.len());
            let mut tasks = vec![];
            for neighbor in neighbors {
                let p = Arc::clone(proto);
                tasks.push(tokio::spawn(async move {
                    p.call_leave_rpc(&neighbor).await;
                }));
            }
            futures::future::join_all(tasks).await;
        }
        if let Some(h) = self.refresh_loop.take() {
            h.abort();
        }
        if let Some(h) = self.save_state_loop.take() {
            h.abort();
        }
    }

    /// Bootstrap the node by contacting a list of known peers.
    ///
    /// Returns the k-closest nodes discovered during the initial lookup.
    pub async fn bootstrap(&self, addrs: Vec<(String, u16)>) -> Vec<Node> {
        log::debug!("Bootstrapping with {} initial contacts", addrs.len());
        println!(">>> Bootstrapping with {} initial contacts", addrs.len());
        let mut futs = vec![];
        for addr in addrs {
            futs.push(self.bootstrap_node(addr));
        }
        let nodes: Vec<Node> = futures::future::join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect();

        match &self.protocol {
            Some(proto) => {
                NodeSpiderCrawl::new(
                    Arc::clone(proto),
                    self.node.clone(),
                    nodes,
                    self.ksize,
                    self.alpha,
                )
                .find()
                .await
            }
            None => vec![],
        }
    }

    async fn bootstrap_node(&self, addr: (String, u16)) -> Option<Node> {
        let proto = self.protocol.as_ref()?;
        let (ok, id_bytes) = proto.call_ping_addr(&addr).await;
        if !ok || id_bytes.len() != ID_LEN {
            return None;
        }
        let mut id = [0u8; ID_LEN];
        id.copy_from_slice(&id_bytes);
        Some(Node::new(id, Some(addr.0), Some(addr.1)))
    }

    /// Look up `key` in the DHT.
    ///
    /// Checks local storage first, then performs an iterative network lookup.
    /// The Dilithium signature is verified on every hit (local via cache, network inline).
    /// Returns `None` if the key is not found or the signature is invalid.
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        log::info!("get({})", key);
        let dkey = digest(key);

        // Local hits are re-verified via the signature cache: first access pays
        // full Dilithium cost; subsequent reads of the same record are O(1).
        // This matches the paper (§4.4): "the requesting node verifies the
        // signature before accepting the record."
        if let Some(result) = self.storage.get(&dkey) {
            return if self.verify_value(key, &result).await {
                Some(result)
            } else {
                None
            };
        }

        let proto = self.protocol.as_ref()?;

        let nearest: Vec<Node> = proto
            .router
            .read()
            .await
            .find_neighbors(&Node::from_id(dkey), None);
        if nearest.is_empty() {
            log::warn!("get({}): no known neighbours", key);
            return None;
        }

        let (result, _) = ValueSpiderCrawl::new(
            Arc::clone(proto),
            Node::from_id(dkey),
            nearest,
            self.ksize,
            self.alpha,
        )
        .find()
        .await;

        match result {
            Some(v) if self.verify_value(key, &v).await => Some(v),
            _ => None,
        }
    }

    /// Used by `set()` only: performs a FIND_VALUE crawl and also returns the
    /// k-closest nodes so they can be reused for the subsequent STORE without a
    async fn check_exists_and_get_nodes(&self, key: &str) -> (bool, Vec<Node>) {
        let dkey = digest(key);

        if self.storage.get(&dkey).is_some() {
            return (true, vec![]);
        }

        let proto = match self.protocol.as_ref() {
            Some(p) => p,
            None => return (false, vec![]),
        };

        let nearest: Vec<Node> = proto
            .router
            .read()
            .await
            .find_neighbors(&Node::from_id(dkey), None);
        if nearest.is_empty() {
            log::warn!("set({}): no known neighbours", key);
            return (false, vec![]);
        }

        let (result, nodes) = ValueSpiderCrawl::new(
            Arc::clone(proto),
            Node::from_id(dkey),
            nearest,
            self.ksize,
            self.alpha,
        )
        .find()
        .await;

        match result {
            // Verify before trusting: an invalid signature means no legitimate
            // record exists at this key — the nodes are still usable for STORE.
            Some(v) if self.verify_value(key, &v).await => (true, vec![]),
            Some(_) => (false, nodes), // Invalid Signature case, but returns nodes to store the right DID Documet
            None => (false, nodes),
        }
    }

    /// Store `value` under `key` in the DHT.
    ///
    /// Returns `None` if the key already exists or the signature is invalid.
    pub async fn set(&self, key: &str, value: Vec<u8>) -> Option<bool> {
        let (exists, nodes) = self.check_exists_and_get_nodes(key).await;
        if exists {
            log::error!("set({}): record already exists", key);
            return None;
        }
        if !self.verify_value(key, &value).await {
            log::error!("set({}): invalid signature", key);
            return None;
        }
        log::info!("set({}): publishing to network", key);
        let dkey = digest(key);
        Some(self.set_digest(dkey, value, nodes).await)
    }

    /// Update an existing record.
    ///
    /// For regular DID Documents `auth_signature` must be a signature of
    /// `value` produced with the private key of the *current* DID Document.
    /// For the status-list key, `auth_signature` may be `None` (the issuer
    /// node signature embedded in `value` is sufficient).
    pub async fn update(
        &self,
        key: &str,
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> Option<bool> {
        let old_value = self.get(key).await?;

        let handler = Arc::clone(&self.signature_handler);
        let is_status = key == STATUS_LIST_KEY && auth_signature.is_none();
        let v = value.clone();
        let auth = auth_signature.clone();
        let ok = tokio::task::spawn_blocking(move || {
            if is_status {
                handler
                    .handle_issuer_node_signature_verification(&v)
                    .unwrap_or(false)
            } else {
                handler
                    .handle_update_verification(&v, &old_value, auth.as_deref().unwrap_or_default())
                    .unwrap_or(false)
            }
        })
        .await
        .unwrap_or(false);

        if !ok {
            log::error!("update({}): unauthenticated", key);
            return None;
        }
        log::info!("update({}): authenticated, publishing", key);
        let dkey = digest(key);
        Some(self.update_digest(key, dkey, value, auth_signature).await)
    }

    /// Delete an existing record.
    ///
    /// `auth_signature` must be a signature of `delete_msg` produced with the
    /// private key corresponding to the stored DID Document's public key.
    pub async fn delete(
        &self,
        key: &str,
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> Option<bool> {
        let value = self.get(key).await?;

        let handler = Arc::clone(&self.signature_handler);
        let auth_c = auth_signature.clone();
        let msg_c = delete_msg.clone();
        let ok = tokio::task::spawn_blocking(move || {
            handler
                .handle_signature_delete_operation(&value, &auth_c, &msg_c)
                .unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if !ok {
            log::error!("delete({}): invalid signature", key);
            return None;
        }
        log::info!("delete({}): verified, removing from network", key);
        let dkey = digest(key);
        Some(self.delete_digest(dkey, auth_signature, delete_msg).await)
    }

    async fn set_digest(&self, dkey: [u8; ID_LEN], value: Vec<u8>, nodes: Vec<Node>) -> bool {
        let proto = match &self.protocol {
            Some(p) => p,
            None => return false,
        };

        if nodes.is_empty() {
            log::warn!("set_digest {}: no nodes from lookup", hex::encode(dkey));
            return false;
        }

        let node = Node::from_id(dkey);

        log::info!(
            "set_digest {}: storing on {} nodes",
            hex::encode(dkey),
            nodes.len()
        );

        if let Some(farthest) = nodes.iter().map(|n| n.distance_to(&node)).max() {
            if self.node.distance_to(&node) < farthest {
                self.storage.set(dkey.to_vec(), value.clone());
            }
        }

        let mut futs = vec![];
        for n in &nodes {
            let p = Arc::clone(proto);
            let n = n.clone();
            let v = value.clone();
            futs.push(async move { p.call_store_rpc(&n, dkey, v).await });
        }
        let results = futures::future::join_all(futs).await;
        let ok_count = results.iter().filter(|&&r| r).count();
        if ok_count == 0 {
            log::warn!(
                "set_digest {}: all {} store RPCs failed",
                hex::encode(dkey),
                results.len()
            );
        } else {
            log::info!(
                "set_digest {}: {}/{} nodes acknowledged store",
                hex::encode(dkey),
                ok_count,
                results.len()
            );
        }
        ok_count > 0
    }

    async fn update_digest(
        &self,
        key: &str,
        dkey: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Option<Vec<u8>>,
    ) -> bool {
        let proto = match &self.protocol {
            Some(p) => p,
            None => return false,
        };
        let node = Node::from_id(dkey);
        let nearest = proto.router.read().await.find_neighbors(&node, None);
        if nearest.is_empty() {
            log::warn!("update_digest {}: no neighbours", key);
            return false;
        }

        let nodes = NodeSpiderCrawl::new(
            Arc::clone(proto),
            node.clone(),
            nearest,
            self.ksize,
            self.alpha,
        )
        .find()
        .await;

        if let Some(farthest) = nodes.iter().map(|n| n.distance_to(&node)).max() {
            if self.node.distance_to(&node) < farthest {
                self.storage.set(dkey.to_vec(), value.clone());
            }
        }

        let is_status_list = key == STATUS_LIST_KEY;
        let mut futs: Vec<std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>>> =
            vec![];

        for n in &nodes {
            let p = Arc::clone(proto);
            let n = n.clone();
            let v = value.clone();
            if is_status_list {
                futs.push(Box::pin(async move {
                    p.call_status_list_update_rpc(&n, dkey, v).await
                }));
            } else {
                let sig = auth_signature.clone().unwrap_or_default();
                futs.push(Box::pin(async move {
                    p.call_update_rpc(&n, dkey, v, sig).await
                }));
            }
        }

        futures::future::join_all(futs).await.iter().any(|&r| r)
    }

    async fn delete_digest(
        &self,
        dkey: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> bool {
        let proto = match &self.protocol {
            Some(p) => p,
            None => return false,
        };

        // Always delete locally first — the caller has already verified the
        // signature and confirmed the record exists.
        self.storage.delete(&dkey);

        let node = Node::from_id(dkey);
        let nearest = proto.router.read().await.find_neighbors(&node, None);
        if nearest.is_empty() {
            log::warn!(
                "delete_digest {}: no neighbours, local delete only",
                hex::encode(dkey)
            );
            return true;
        }

        let nodes = NodeSpiderCrawl::new(Arc::clone(proto), node, nearest, self.ksize, self.alpha)
            .find()
            .await;

        log::info!(
            "delete_digest {}: propagating to {} nodes",
            hex::encode(dkey),
            nodes.len()
        );

        let mut futs = vec![];
        for n in &nodes {
            let p = Arc::clone(proto);
            let n = n.clone();
            let sig = auth_signature.clone();
            let msg = delete_msg.clone();
            futs.push(async move { p.call_delete_rpc(&n, dkey, sig, msg).await });
        }
        futures::future::join_all(futs).await;
        true
    }

    async fn verify_value(&self, key: &str, value: &[u8]) -> bool {
        let is_status = key == STATUS_LIST_KEY;
        let cache_key = self
            .sig_cache
            .as_ref()
            .map(|_| SignatureCache::compute_key(value));
        if let (Some(cache), Some(ck)) = (&self.sig_cache, &cache_key) {
            if let Some(cached) = cache.get_by_key(ck) {
                return cached;
            }
        }
        let handler = Arc::clone(&self.signature_handler);
        let v = value.to_vec();
        let result = tokio::task::spawn_blocking(move || {
            if is_status {
                handler
                    .handle_issuer_node_signature_verification(&v)
                    .unwrap_or(false)
            } else {
                handler.handle_signature_verification(&v).unwrap_or(false)
            }
        })
        .await
        .unwrap_or(false);
        if result && is_status {
            log::info!("Status-list signature verified");
        }
        if let (Some(cache), Some(ck)) = (&self.sig_cache, cache_key) {
            cache.insert_by_key(ck, result);
        }
        result
    }

    /// Return the addresses of bootstrappable neighbour nodes.
    pub async fn bootstrappable_neighbors(&self) -> Vec<(String, u16)> {
        match &self.protocol {
            Some(proto) => proto
                .router
                .read()
                .await
                .find_neighbors(&self.node, None)
                .into_iter()
                .filter_map(|n| n.address())
                .collect(),
            None => vec![],
        }
    }

    /// Save node state (ksize, alpha, id, neighbours) to a JSON file.
    pub async fn save_state(&self, fname: &str) {
        let neighbors = self.bootstrappable_neighbors().await;
        if neighbors.is_empty() {
            log::warn!("save_state: no neighbours, skipping");
            return;
        }
        let data = serde_json::json!({
            "ksize": self.ksize,
            "alpha": self.alpha,
            "id": hex::encode(self.node.id),
            "neighbors": neighbors,
        });
        if let Ok(json) = serde_json::to_string_pretty(&data) {
            if let Err(e) = std::fs::write(fname, json) {
                log::error!("save_state: failed to write {}: {}", fname, e);
            }
        }
    }

    /// Start a background task that saves node state every `frequency_secs` seconds.
    pub fn save_state_regularly(&mut self, fname: String, frequency_secs: u64) {
        let node = self.node.clone();
        let ksize = self.ksize;
        let alpha = self.alpha;
        if let Some(proto) = &self.protocol {
            let proto = Arc::clone(proto);
            let handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(frequency_secs)).await;
                    let neighbors: Vec<_> = proto
                        .router
                        .read()
                        .await
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

    fn schedule_refresh(&mut self) {
        let proto = match &self.protocol {
            Some(p) => Arc::clone(p),
            None => return,
        };
        let storage = Arc::clone(&self.storage);
        let ksize = self.ksize;
        let alpha = self.alpha;

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
                log::debug!("Routing table refresh triggered");

                let refresh_ids = proto.get_refresh_ids().await;
                let mut futs = vec![];
                for rid in refresh_ids {
                    let rnode = Node::from_id(rid);
                    let neighbors = proto.router.read().await.find_neighbors(&rnode, None);
                    let spider =
                        NodeSpiderCrawl::new(Arc::clone(&proto), rnode, neighbors, ksize, alpha);
                    futs.push(spider.find());
                }
                futures::future::join_all(futs).await;

                let old_entries = storage.iter_older_than(3600);
                for (key_vec, value) in old_entries {
                    if key_vec.len() != ID_LEN {
                        continue;
                    }
                    let mut dkey = [0u8; ID_LEN];
                    dkey.copy_from_slice(&key_vec);
                    let target = Node::from_id(dkey);
                    let neighbors = proto.router.read().await.find_neighbors(&target, None);
                    if neighbors.is_empty() {
                        continue;
                    }
                    let nodes =
                        NodeSpiderCrawl::new(Arc::clone(&proto), target, neighbors, ksize, alpha)
                            .find()
                            .await;

                    let mut store_futs = vec![];
                    for n in &nodes {
                        let p = Arc::clone(&proto);
                        let n = n.clone();
                        let v = value.clone();
                        store_futs.push(async move { p.call_store_rpc(&n, dkey, v).await });
                    }
                    futures::future::join_all(store_futs).await;
                }
            }
        });
        self.refresh_loop = Some(handle);
    }
}
