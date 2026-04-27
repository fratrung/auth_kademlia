/// Kademlia protocol layer with a real UDP transport.
///
/// `KademliaProtocol` owns the UDP socket, serialises/deserialises messages
/// with `bincode`, dispatches incoming RPCs to the appropriate handler, and
/// exposes `call_*` methods for sending outbound RPCs to remote peers.
///
/// Message framing: every datagram is a `bincode`-encoded `(u32 msg_id, RpcEnvelope)`.
/// Responses are correlated by `msg_id` via a `PendingMap`.
/// 
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use log;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{oneshot, Mutex};
use tokio::time::timeout;

use crate::auth_handler::SignatureVerifierHandler;
use crate::crawling::{FindPayload, RawResponse, SpiderProtocol};
use crate::node::Node;
use crate::routing::RoutingTable;
use crate::storage::{ForgetfulStorage, IStorage};
use crate::utils::{digest, ID_LEN};
use crate::fragmentation::{MAX_MESSAGE_SIZE, FRAG_CHUNK_SIZE, REASSEMBLY_TTL, ReassemblyEntry, ReassemblyMap, encode_fragments, parse_fragment};

/// Timeout for a single RPC call.
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

const STATUS_LIST_KEY: &str = "did:iiot:status-list";


/// Messages sent over the wire. Each variant corresponds to a Kademlia RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RpcMessage {
    Ping {
        sender_id: [u8; ID_LEN],
    },
    Pong {
        sender_id: [u8; ID_LEN],
    },
    Store {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
    },
    StoreResult {
        ok: bool,
    },
    Update {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    },
    UpdateResult {
        ok: bool,
    },
    UpdateStatusList {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        value: Vec<u8>,
    },
    UpdateStatusListResult {
        ok: bool,
    },
    Delete {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    },
    DeleteResult {
        ok: bool,
    },
    FindNode {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindNodeResult {
        nodes: Vec<WireNode>,
    },
    FindValue {
        sender_id: [u8; ID_LEN],
        key: [u8; ID_LEN],
    },
    FindValueNodes {
        nodes: Vec<WireNode>,
    },
    FindValueHit {
        value: Vec<u8>,
    },
    Leave {
        sender_id: [u8; ID_LEN],
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireNode {
    pub id: [u8; ID_LEN],
    pub ip: Option<String>,
    pub port: Option<u16>,
}

impl From<&Node> for WireNode {
    fn from(n: &Node) -> Self {
        Self { id: n.id, ip: n.ip.clone(), port: n.port }
    }
}

impl From<WireNode> for Node {
    fn from(w: WireNode) -> Self {
        Node::new(w.id, w.ip, w.port)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Frame {
    msg_id: u32,
    is_request: bool,
    message: RpcMessage,
}

type PendingMap = Arc<Mutex<HashMap<u32, oneshot::Sender<RpcMessage>>>>;


pub struct KademliaProtocol {
    pub router: Arc<Mutex<RoutingTable>>,
    pub storage: Arc<Mutex<ForgetfulStorage>>,
    pub source_node: Node,
    pub socket: Arc<UdpSocket>,
    pub signature_handler: Arc<dyn SignatureVerifierHandler>,
    pending: PendingMap,
    next_msg_id: Arc<Mutex<u32>>,
    next_frag_id: Arc<Mutex<u32>>,
    reassembly: ReassemblyMap,
}

impl KademliaProtocol {
    pub fn new(
        source_node: Node,
        socket: Arc<UdpSocket>,
        storage: Arc<Mutex<ForgetfulStorage>>,
        ksize: usize,
        signature_handler: Arc<dyn SignatureVerifierHandler>,
    ) -> Self {
        let router = RoutingTable::new(source_node.clone(), ksize);
        Self {
            router: Arc::new(Mutex::new(router)),
            storage,
            source_node,
            socket,
            signature_handler,
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_msg_id: Arc::new(Mutex::new(0)),
            next_frag_id: Arc::new(Mutex::new(0)),
            reassembly: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn next_id(&self) -> u32 {
        let mut id = self.next_msg_id.lock().await;
        let out = *id;
        *id = id.wrapping_add(1);
        out
    }

    async fn next_frag_id(&self) -> u32 {
        let mut id = self.next_frag_id.lock().await;
        let out = *id;
        *id = id.wrapping_add(1);
        out
    }

    /// Drop reassembly buffers older than `REASSEMBLY_TTL`. Called opportunistically
    /// to bound memory usage in the face of lost fragments.
    async fn gc_reassembly(&self) {
        let now = Instant::now();
        let mut map = self.reassembly.lock().await;
        map.retain(|_, entry| now.duration_since(entry.created_at) < REASSEMBLY_TTL);
    }

    /// Serialize, fragment, and send a frame to `addr`. Returns false if any
    /// fragment fails to be transmitted.
    async fn send_frame(&self, addr: SocketAddr, frame: &Frame) -> bool {
        let bytes = match bincode::serialize(frame) {
            Ok(b) => b,
            Err(e) => {
                log::error!("Serialization error: {}", e);
                return false;
            }
        };

        if bytes.len() > MAX_MESSAGE_SIZE {
            log::error!(
                "Refusing to send {} byte message (limit {})",
                bytes.len(),
                MAX_MESSAGE_SIZE
            );
            return false;
        }

        let frag_id = self.next_frag_id().await;
        let datagrams = encode_fragments(frag_id, &bytes);

        if datagrams.len() > 1 {
            log::debug!(
                "Sending {} byte frame to {} as {} fragments (frag_id={})",
                bytes.len(),
                addr,
                datagrams.len(),
                frag_id
            );
        }

        for dg in &datagrams {
            if let Err(e) = self.socket.send_to(dg, addr).await {
                log::warn!("UDP send to {} failed: {}", addr, e);
                return false;
            }
        }
        true
    }

    /// Send an RPC request to `addr` and wait for the matching response.
    async fn call(&self, addr: SocketAddr, message: RpcMessage) -> Option<RpcMessage> {
        let msg_id = self.next_id().await;
        let frame = Frame { msg_id, is_request: true, message };

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(msg_id, tx);

        if !self.send_frame(addr, &frame).await {
            self.pending.lock().await.remove(&msg_id);
            return None;
        }

        match timeout(RPC_TIMEOUT, rx).await {
            Ok(Ok(response)) => Some(response),
            Ok(Err(_)) => {
                log::debug!("Response channel closed for msg_id={}", msg_id);
                None
            }
            Err(_) => {
                log::debug!("RPC timeout for msg_id={}", msg_id);
                self.pending.lock().await.remove(&msg_id);
                None
            }
        }
    }

    /// Parse and dispatch an incoming UDP datagram.
    /// Datagrams are reassembled from fragments before being deserialized.
    /// Responses are routed to waiting `call()` callers via the pending map.
    /// Requests are handled inline and a response is sent back.
    pub async fn handle_datagram(self: &Arc<Self>, data: Vec<u8>, peer: SocketAddr) {
        // Step 1: parse fragment header.
        let (header, chunk) = match parse_fragment(&data) {
            Some(parts) => parts,
            None => {
                log::warn!("Discarded datagram from {} without valid fragment header", peer);
                return;
            }
        };

        // Step 2: reassemble. Single-fragment messages are handled without
        // touching the reassembly map for the common case.
        let payload: Vec<u8> = if header.total == 1 {
            chunk.to_vec()
        } else {
            // Bound memory usage upfront: refuse fragments that would push the
            // logical message over the size limit.
            let projected = (header.total as usize).saturating_mul(FRAG_CHUNK_SIZE);
            if projected > MAX_MESSAGE_SIZE {
                log::warn!(
                    "Discarded oversized fragmented message from {} ({} fragments)",
                    peer,
                    header.total
                );
                return;
            }

            let key = (peer, header.frag_id);
            let mut map = self.reassembly.lock().await;

            // Insert/get entry, validate consistency, and record the chunk in
            // a scope that releases the &mut borrow before we call remove().
            let complete = {
                let entry = map
                    .entry(key)
                    .or_insert_with(|| ReassemblyEntry::new(header.total));

                if entry.total != header.total {
                    log::warn!(
                        "Inconsistent total for frag_id={} from {} (got {}, expected {})",
                        header.frag_id,
                        peer,
                        header.total,
                        entry.total
                    );
                    return;
                }
                entry.insert(header.index, chunk.to_vec())
            };

            if !complete {
                drop(map);
                // Opportunistic GC of stale buffers.
                self.gc_reassembly().await;
                return;
            }

            // All fragments received: take ownership and assemble.
            let entry = map.remove(&key).expect("entry checked above");
            drop(map);
            match entry.assemble() {
                Some(p) => p,
                None => {
                    log::warn!("Assembly failed for frag_id={} from {}", header.frag_id, peer);
                    return;
                }
            }
        };

        // Step 3: deserialize and dispatch.
        let frame: Frame = match bincode::deserialize(&payload) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Failed to deserialize: {}", e);
                return;
            }
        };

        if !frame.is_request {
            if let RpcMessage::Pong { sender_id } = &frame.message {
                let source = Node::new(*sender_id, Some(peer.ip().to_string()), Some(peer.port()));
                let p = Arc::clone(self);
                tokio::spawn(async move {
                    p.welcome_if_new(source).await;
                });
            }

            if let Some(tx) = self.pending.lock().await.remove(&frame.msg_id) {
                let _ = tx.send(frame.message);
            }
            return;
        }

        let response = self.dispatch_request(frame.message, peer).await;
        if let Some(resp) = response {
            let resp_frame = Frame {
                msg_id: frame.msg_id,
                is_request: false,
                message: resp,
            };
            self.send_frame(peer, &resp_frame).await;
        }
    }

    async fn dispatch_request(
        &self,
        msg: RpcMessage,
        peer: SocketAddr,
    ) -> Option<RpcMessage> {
        let sender_addr = (peer.ip().to_string(), peer.port());
        match msg {
            RpcMessage::Ping { sender_id } => {
                let resp_id = self.rpc_ping(sender_id, sender_addr).await;
                Some(RpcMessage::Pong { sender_id: resp_id })
            }
            RpcMessage::Store { sender_id, key, value } => {
                let ok = self.rpc_store(sender_id, sender_addr, key, value).await;
                Some(RpcMessage::StoreResult { ok })
            }
            RpcMessage::Update { sender_id, key, value, auth_signature } => {
                let ok = self.rpc_update(sender_id, sender_addr, key, value, auth_signature).await;
                Some(RpcMessage::UpdateResult { ok })
            }
            RpcMessage::UpdateStatusList { sender_id, key, value } => {
                let ok = self.rpc_update_status_list(sender_id, sender_addr, key, value).await;
                Some(RpcMessage::UpdateStatusListResult { ok })
            }
            RpcMessage::Delete { sender_id, key, auth_signature, delete_msg } => {
                let ok = self.rpc_delete(sender_id, sender_addr, key, auth_signature, delete_msg).await;
                Some(RpcMessage::DeleteResult { ok })
            }
            RpcMessage::FindNode { sender_id, key } => {
                let nodes = self.rpc_find_node(sender_id, sender_addr, key).await;
                Some(RpcMessage::FindNodeResult {
                    nodes: nodes.iter().map(WireNode::from).collect(),
                })
            }
            RpcMessage::FindValue { sender_id, key } => {
                let result = self.rpc_find_value(sender_id, sender_addr, key).await;
                Some(match result {
                    FindValueResult::Value(v) => RpcMessage::FindValueHit { value: v },
                    FindValueResult::Nodes(ns) => RpcMessage::FindValueNodes {
                        nodes: ns.iter().map(WireNode::from).collect(),
                    },
                })
            }
            RpcMessage::Leave { sender_id } => {
                self.rpc_leave(sender_id, sender_addr).await;
                None // no response to leave
            }
            _ => {
                log::warn!("Received unexpected message type");
                None
            }
        }
    }


    pub async fn rpc_ping(
        &self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
    ) -> [u8; ID_LEN] {
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.source_node.id
    }

    pub async fn rpc_store(
        &self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        if self.storage.lock().await.get(&key).is_some() {
            log::error!("rpc_store: record {} already exists", hex::encode(key));
            return false;
        }
        if !self.verify_for_key(&key, &value) {
            log::error!("rpc_store: invalid signature for {}", hex::encode(key));
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.storage.lock().await.set(key.to_vec(), value);
        true
    }

    pub async fn rpc_update(
        &self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> bool {
        let old_value = match self.storage.lock().await.get(&key) {
            Some(v) => v,
            None => {
                log::error!("rpc_update: record {} not found", hex::encode(key));
                return false;
            }
        };
        let ok = self
            .signature_handler
            .handle_update_verification(&value, &old_value, &auth_signature)
            .unwrap_or(false);
        if !ok {
            log::error!("rpc_update: unauthenticated update for {}", hex::encode(key));
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.storage.lock().await.set(key.to_vec(), value);
        true
    }

    pub async fn rpc_update_status_list(
        &self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        if self.storage.lock().await.get(&key).is_none() {
            log::error!("rpc_update_status_list: record {} not found", hex::encode(key));
            return false;
        }
        let ok = self
            .signature_handler
            .handle_issuer_node_signature_verification(&value)
            .unwrap_or(false);
        if !ok {
            log::error!("rpc_update_status_list: unauthenticated update");
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.storage.lock().await.set(key.to_vec(), value);
        true
    }

    pub async fn rpc_delete(
        &self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> bool {
        let value = match self.storage.lock().await.get(&key) {
            Some(v) => v,
            None => {
                log::error!("rpc_delete: record {} not found", hex::encode(key));
                return false;
            }
        };
        let ok = self
            .signature_handler
            .handle_signature_delete_operation(&value, &auth_signature, &delete_msg)
            .unwrap_or(false);
        if !ok {
            log::error!("rpc_delete: invalid signature for {}", hex::encode(key));
            return false;
        }
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.welcome_if_new(source).await;
        self.storage.lock().await.delete(&key);
        true
    }

    pub async fn rpc_find_node(
        &self,
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
        &self,
        sender_id: [u8; ID_LEN],
        sender_addr: (String, u16),
        key: [u8; ID_LEN],
    ) -> FindValueResult {
        let source = Node::new(sender_id, Some(sender_addr.0.clone()), Some(sender_addr.1));
        self.welcome_if_new(source.clone()).await;
        match self.storage.lock().await.get(&key) {
            Some(v) => FindValueResult::Value(v),
            None => {
                let neighbors = self.rpc_find_node(sender_id, sender_addr, key).await;
                FindValueResult::Nodes(neighbors)
            }
        }
    }

    pub async fn rpc_leave(&self, sender_id: [u8; ID_LEN], sender_addr: (String, u16)) {
        log::info!("Node {} is leaving the network", hex::encode(sender_id));
        let source = Node::new(sender_id, Some(sender_addr.0), Some(sender_addr.1));
        self.router.lock().await.remove_contact(&source);
    }


    pub async fn call_ping_addr(&self, addr: &(String, u16)) -> (bool, Vec<u8>) {
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return (false, vec![]),
        };
        let resp = self.call(sock_addr, RpcMessage::Ping { sender_id: self.source_node.id }).await;
        match resp {
            Some(RpcMessage::Pong { sender_id }) => (true, sender_id.to_vec()),
            _ => (false, vec![]),
        }
    }

    pub async fn call_store_rpc(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool {
        let addr = match peer.address() {
            Some(a) => a,
            None => return false,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        match self
            .call(sock_addr, RpcMessage::Store { sender_id: self.source_node.id, key, value })
            .await
        {
            Some(RpcMessage::StoreResult { ok }) => ok,
            _ => false,
        }
    }

    pub async fn call_update_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
        auth_signature: Vec<u8>,
    ) -> bool {
        let addr = match peer.address() {
            Some(a) => a,
            None => return false,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        match self
            .call(
                sock_addr,
                RpcMessage::Update {
                    sender_id: self.source_node.id,
                    key,
                    value,
                    auth_signature,
                },
            )
            .await
        {
            Some(RpcMessage::UpdateResult { ok }) => ok,
            _ => false,
        }
    }

    pub async fn call_status_list_update_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        value: Vec<u8>,
    ) -> bool {
        let addr = match peer.address() {
            Some(a) => a,
            None => return false,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        match self
            .call(
                sock_addr,
                RpcMessage::UpdateStatusList { sender_id: self.source_node.id, key, value },
            )
            .await
        {
            Some(RpcMessage::UpdateStatusListResult { ok }) => ok,
            _ => false,
        }
    }

    pub async fn call_delete_rpc(
        &self,
        peer: &Node,
        key: [u8; ID_LEN],
        auth_signature: Vec<u8>,
        delete_msg: Vec<u8>,
    ) -> bool {
        let addr = match peer.address() {
            Some(a) => a,
            None => return false,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        match self
            .call(
                sock_addr,
                RpcMessage::Delete {
                    sender_id: self.source_node.id,
                    key,
                    auth_signature,
                    delete_msg,
                },
            )
            .await
        {
            Some(RpcMessage::DeleteResult { ok }) => ok,
            _ => false,
        }
    }

    pub async fn call_leave_rpc(&self, peer: &Node) {
        let addr = match peer.address() {
            Some(a) => a,
            None => return,
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return,
        };
        // Fire-and-forget: we don't wait for a response.
        let _ = self
            .call(sock_addr, RpcMessage::Leave { sender_id: self.source_node.id })
            .await;
    }


    fn verify_for_key(&self, key: &[u8; ID_LEN], value: &[u8]) -> bool {
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

    /// If `node` is new, add it to the routing table and replicate relevant
    /// keys to it (Kademlia §2.5 — new node integration).
    pub async fn welcome_if_new(&self, node: Node) {
        if !self.router.lock().await.is_new_node(&node) {
            return;
        }
        log::info!("New node discovered: {}", node);

        let all_entries = self.storage.lock().await.iter_all();
        let self_node = self.source_node.clone();
        let node_clone = node.clone();

        let keys_to_replicate: Vec<([u8; ID_LEN], Vec<u8>)> = {
            let router = self.router.lock().await;
            all_entries
                .into_iter()
                .filter_map(|(key_vec, value)| {
                    if key_vec.len() != ID_LEN {
                        return None;
                    }
                    let mut key = [0u8; ID_LEN];
                    key.copy_from_slice(&key_vec);
                    let key_node = Node::from_id(key);
                    let neighbors = router.find_neighbors(&key_node, None);

                    // Replicate if the new node is closer than our farthest
                    // neighbor and we are the closest existing node.
                    let new_dist = node_clone.distance_to(&key_node);
                    let self_dist = self_node.distance_to(&key_node);
                    let farthest_dist = neighbors.last().map(|n| n.distance_to(&key_node));

                    let should_replicate = farthest_dist
                        .map(|fd| new_dist < fd && self_dist < fd)
                        .unwrap_or(true); // no neighbors yet -> always replicate

                    if should_replicate { Some((key, value)) } else { None }
                })
                .collect()
        };

        self.router.lock().await.add_contact(node.clone());

        // Send store RPCs for keys the new node should hold.
        for (key, value) in keys_to_replicate {
            self.call_store_rpc(&node, key, value).await;
        }
    }

    /// Return a random ID for each bucket that needs refreshing.
    pub async fn get_refresh_ids(&self) -> Vec<[u8; ID_LEN]> {
        use rand::RngCore;
        self.router
            .lock()
            .await
            .lonely_buckets()
            .iter()
            .map(|_| {
                let mut id = [0u8; ID_LEN];
                rand::thread_rng().fill_bytes(&mut id);
                id
            })
            .collect()
    }
}


pub enum FindValueResult {
    Nodes(Vec<Node>),
    Value(Vec<u8>),
}

#[async_trait]
impl SpiderProtocol for KademliaProtocol {
    async fn call_find_node(&self, peer: &Node, target: &Node) -> RawResponse {
        let addr = match peer.address() {
            Some(a) => a,
            None => return RawResponse(false, FindPayload::Empty),
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return RawResponse(false, FindPayload::Empty),
        };
        match self
            .call(
                sock_addr,
                RpcMessage::FindNode { sender_id: self.source_node.id, key: target.id },
            )
            .await
        {
            Some(RpcMessage::FindNodeResult { nodes }) => {
                let tuples = nodes
                    .into_iter()
                    .map(|w| (w.id.to_vec(), w.ip, w.port))
                    .collect();
                RawResponse(true, FindPayload::Nodes(tuples))
            }
            _ => RawResponse(false, FindPayload::Empty),
        }
    }

    async fn call_find_value(&self, peer: &Node, target: &Node) -> RawResponse {
        let addr = match peer.address() {
            Some(a) => a,
            None => return RawResponse(false, FindPayload::Empty),
        };
        let sock_addr: SocketAddr = match format!("{}:{}", addr.0, addr.1).parse() {
            Ok(a) => a,
            Err(_) => return RawResponse(false, FindPayload::Empty),
        };
        match self
            .call(
                sock_addr,
                RpcMessage::FindValue { sender_id: self.source_node.id, key: target.id },
            )
            .await
        {
            Some(RpcMessage::FindValueHit { value }) => {
                RawResponse(true, FindPayload::Value(value))
            }
            Some(RpcMessage::FindValueNodes { nodes }) => {
                let tuples = nodes
                    .into_iter()
                    .map(|w| (w.id.to_vec(), w.ip, w.port))
                    .collect();
                RawResponse(true, FindPayload::Nodes(tuples))
            }
            _ => RawResponse(false, FindPayload::Empty),
        }
    }

    async fn call_store(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool {
        self.call_store_rpc(peer, key, value).await
    }
}