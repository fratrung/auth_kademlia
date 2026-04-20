/// Kademlia protocol layer with a real UDP transport.
///
/// `KademliaProtocol` owns the UDP socket, serialises/deserialises messages
/// with `bincode`, dispatches incoming RPCs to the appropriate handler, and
/// exposes `call_*` methods for sending outbound RPCs to remote peers.
///
/// Message framing: every datagram is a `bincode`-encoded `(u32 msg_id, RpcEnvelope)`.
/// Responses are correlated by `msg_id` via a `PendingMap`.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Timeout for a single RPC call.
const RPC_TIMEOUT: Duration = Duration::from_secs(5);

const STATUS_LIST_KEY: &str = "did:iiot:status-list";

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

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

/// A compact node representation suitable for wire serialization.
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

/// Framed datagram: `(message_id, payload)`.
#[derive(Debug, Serialize, Deserialize)]
struct Frame {
    msg_id: u32,
    /// `true` for requests, `false` for responses.
    is_request: bool,
    message: RpcMessage,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pending RPC tracking
// ─────────────────────────────────────────────────────────────────────────────

type PendingMap = Arc<Mutex<HashMap<u32, oneshot::Sender<RpcMessage>>>>;

// ─────────────────────────────────────────────────────────────────────────────
// KademliaProtocol
// ─────────────────────────────────────────────────────────────────────────────

pub struct KademliaProtocol {
    pub router: Arc<Mutex<RoutingTable>>,
    pub storage: Arc<Mutex<ForgetfulStorage>>,
    pub source_node: Node,
    pub socket: Arc<UdpSocket>,
    pub signature_handler: Arc<dyn SignatureVerifierHandler>,
    pending: PendingMap,
    next_msg_id: Arc<Mutex<u32>>,
}

impl KademliaProtocol {
    /// Create a new protocol instance bound to `socket`.
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
        }
    }

    // ─── Message ID allocation ────────────────────────────────────────────────

    async fn next_id(&self) -> u32 {
        let mut id = self.next_msg_id.lock().await;
        let out = *id;
        *id = id.wrapping_add(1);
        out
    }

    // ─── Transport helpers ────────────────────────────────────────────────────

    /// Send a frame to `addr`.
    async fn send_frame(&self, addr: SocketAddr, frame: &Frame) -> bool {
        match bincode::serialize(frame) {
            Ok(bytes) => {
                if let Err(e) = self.socket.send_to(&bytes, addr).await {
                    log::warn!("UDP send to {} failed: {}", addr, e);
                    false
                } else {
                    true
                }
            }
            Err(e) => {
                log::error!("Serialization error: {}", e);
                false
            }
        }
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
    ///
    /// Responses are routed to waiting `call()` callers via the pending map.
    /// Requests are handled inline and a response is sent back.
    pub async fn handle_datagram(self: &Arc<Self>, data: Vec<u8>, peer: SocketAddr) {
        let frame: Frame = match bincode::deserialize(&data) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Failed to deserialize datagram from {}: {}", peer, e);
                return;
            }
        };

        if !frame.is_request {
            // Route response to the waiting caller.
            if let Some(tx) = self.pending.lock().await.remove(&frame.msg_id) {
                let _ = tx.send(frame.message);
            }
            return;
        }

        // Dispatch request and send response.
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

    /// Dispatch an incoming request to the appropriate RPC handler.
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

    // ─── RPC handlers (incoming) ──────────────────────────────────────────────

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

    // ─── Outbound RPC calls ───────────────────────────────────────────────────

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

    // ─── Internal helpers ─────────────────────────────────────────────────────

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
                        .unwrap_or(true); // no neighbors yet → always replicate

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

// ─────────────────────────────────────────────────────────────────────────────
// FindValueResult
// ─────────────────────────────────────────────────────────────────────────────

pub enum FindValueResult {
    Nodes(Vec<Node>),
    Value(Vec<u8>),
}

// ─────────────────────────────────────────────────────────────────────────────
// SpiderProtocol implementation
// ─────────────────────────────────────────────────────────────────────────────

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
