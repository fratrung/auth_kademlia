/// Exact translation of crawling.py
///
/// SpiderCrawl, ValueSpiderCrawl, NodeSpiderCrawl, RPCFindResponse
use std::collections::HashMap;
use std::sync::Arc;
use log;

use crate::node::{Node, NodeHeap};
use crate::utils::ID_LEN;

// ─────────────────────────────────────────────────────────────────────────────
// RPC response types (what the protocol returns for find_node / find_value)
// ─────────────────────────────────────────────────────────────────────────────

/// The raw tuple a protocol RPC call returns:
///   (response_received: bool, payload: FindPayload)
#[derive(Debug, Clone)]
pub struct RawResponse(pub bool, pub FindPayload);

/// Python: response[1] is either a list of node tuples (find_node)
///         or a dict {'value': v} (find_value)
#[derive(Debug, Clone)]
pub enum FindPayload {
    /// List of (id, ip, port) tuples — from find_node or find_value miss
    Nodes(Vec<(Vec<u8>, Option<String>, Option<u16>)>),
    /// Dict {'value': bytes} — from find_value hit
    Value(Vec<u8>),
    /// No response / None
    Empty,
}

/// Python: RPCFindResponse
pub struct RPCFindResponse {
    response: RawResponse,
}

impl RPCFindResponse {
    pub fn new(response: RawResponse) -> Self {
        Self { response }
    }

    /// Python: response.happened()
    pub fn happened(&self) -> bool {
        self.response.0
    }

    /// Python: response.has_value()
    pub fn has_value(&self) -> bool {
        matches!(self.response.1, FindPayload::Value(_))
    }

    /// Python: response.get_value()
    pub fn get_value(&self) -> Vec<u8> {
        match &self.response.1 {
            FindPayload::Value(v) => v.clone(),
            _ => panic!("get_value called but response has no value"),
        }
    }

    /// Python: response.get_node_list()
    pub fn get_node_list(&self) -> Vec<Node> {
        match &self.response.1 {
            FindPayload::Nodes(tuples) => {
                tuples.iter().map(|(id_bytes, ip, port)| {
                    let mut id = [0u8; ID_LEN];
                    let copy_len = id_bytes.len().min(ID_LEN);
                    id[..copy_len].copy_from_slice(&id_bytes[..copy_len]);
                    Node::new(id, ip.clone(), *port)
                }).collect()
            }
            _ => vec![],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Protocol RPC trait — the spider needs to call into the protocol
// ─────────────────────────────────────────────────────────────────────────────

/// Abstraction over the two RPC methods the spider uses.
/// Implemented by KademliaProtocol (async, over UDP).
#[async_trait::async_trait]
pub trait SpiderProtocol: Send + Sync {
    async fn call_find_node(&self, peer: &Node, target: &Node) -> RawResponse;
    async fn call_find_value(&self, peer: &Node, target: &Node) -> RawResponse;
    async fn call_store(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// SpiderCrawl base
// ─────────────────────────────────────────────────────────────────────────────

/// Python: class SpiderCrawl
pub struct SpiderCrawl<P: SpiderProtocol> {
    pub protocol: Arc<P>,
    pub ksize: usize,
    pub alpha: usize,
    pub node: Node,                   // the key we're looking for
    pub nearest: NodeHeap,
    pub last_ids_crawled: Vec<[u8; ID_LEN]>,
}

impl<P: SpiderProtocol> SpiderCrawl<P> {
    /// Python: SpiderCrawl.__init__
    pub fn new(protocol: Arc<P>, node: Node, peers: Vec<Node>, ksize: usize, alpha: usize) -> Self {
        let mut nearest = NodeHeap::new(node.clone(), ksize);
        log::info!("creating spider with peers: {:?}", peers.iter().map(|p| p.to_string()).collect::<Vec<_>>());
        nearest.push(peers);
        Self {
            protocol,
            ksize,
            alpha,
            node,
            nearest,
            last_ids_crawled: vec![],
        }
    }

    /// Python: SpiderCrawl._find(rpcmethod)
    ///
    /// Calls rpcmethod on up to alpha uncontacted nearest nodes,
    /// collects responses, then calls _nodes_found.
    ///
    /// rpcmethod: async fn(peer, node) -> RawResponse
    pub async fn find_round<F, Fut>(
        &mut self,
        rpcmethod: F,
    ) -> HashMap<[u8; ID_LEN], RawResponse>
    where
        F: Fn(Arc<P>, Node, Node) -> Fut + Clone,
        Fut: std::future::Future<Output = RawResponse> + Send,
    {
        log::info!("crawling with nearest: {}", self.nearest);

        // Python:
        //   count = self.alpha
        //   if self.nearest.get_ids() == self.last_ids_crawled:
        //       count = len(self.nearest)
        let count = if self.nearest.get_ids() == self.last_ids_crawled {
            self.nearest.len()
        } else {
            self.alpha
        };
        self.last_ids_crawled = self.nearest.get_ids();

        // Python: dicts = {}; for peer in nearest.get_uncontacted()[:count]: ...
        let uncontacted: Vec<Node> = self.nearest.get_uncontacted()
            .into_iter()
            .take(count)
            .collect();

        // Mark as contacted, then fire all RPCs concurrently
        let mut futures = Vec::new();
        for peer in &uncontacted {
            self.nearest.mark_contacted(peer);
            let proto = Arc::clone(&self.protocol);
            let peer_clone = peer.clone();
            let node_clone = self.node.clone();
            let f = rpcmethod.clone();
            futures.push((peer.id, async move {
                f(proto, peer_clone, node_clone).await
            }));
        }

        // Python: gather_dict(dicts)
        let mut results = HashMap::new();
        let futs: Vec<_> = futures.into_iter().map(|(id, fut)| async move { (id, fut.await) }).collect();
        let gathered = futures::future::join_all(futs).await;
        for (id, resp) in gathered {
            results.insert(id, resp);
        }
        results
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValueSpiderCrawl
// ─────────────────────────────────────────────────────────────────────────────

/// Python: class ValueSpiderCrawl(SpiderCrawl)
pub struct ValueSpiderCrawl<P: SpiderProtocol> {
    pub base: SpiderCrawl<P>,
    /// Python: self.nearest_without_value = NodeHeap(self.node, 1)
    pub nearest_without_value: NodeHeap,
}

impl<P: SpiderProtocol + 'static> ValueSpiderCrawl<P> {
    pub fn new(protocol: Arc<P>, node: Node, peers: Vec<Node>, ksize: usize, alpha: usize) -> Self {
        let nearest_without_value = NodeHeap::new(node.clone(), 1);
        let base = SpiderCrawl::new(protocol, node, peers, ksize, alpha);
        Self { base, nearest_without_value }
    }

    /// Python: async def find(self)
    pub async fn find(self) -> Option<Vec<u8>> {
        self._find().await
    }

    async fn _find(mut self) -> Option<Vec<u8>> {
        // Python: return await self._find(self.protocol.call_find_value)
        let responses = self.base.find_round(|proto, peer, node| async move {
            proto.call_find_value(&peer, &node).await
        }).await;
        self._nodes_found(responses).await
    }

    /// Python: async def _nodes_found(self, responses)
    async fn _nodes_found(
        mut self,
        responses: HashMap<[u8; ID_LEN], RawResponse>,
    ) -> Option<Vec<u8>> {
        let mut toremove: Vec<[u8; ID_LEN]> = vec![];
        let mut found_values: Vec<Vec<u8>> = vec![];

        for (peerid, response) in &responses {
            let r = RPCFindResponse::new(response.clone());
            if !r.happened() {
                toremove.push(*peerid);
            } else if r.has_value() {
                found_values.push(r.get_value());
            } else {
                // push this peer to nearest_without_value
                if let Some(peer) = self.base.nearest.get_node(peerid) {
                    self.nearest_without_value.push_one(peer);
                }
                self.base.nearest.push(r.get_node_list());
            }
        }
        self.base.nearest.remove(&toremove);

        if !found_values.is_empty() {
            return self._handle_found_values(found_values).await;
        }
        if self.base.nearest.have_contacted_all() {
            // Python: return None (not found)
            return None;
        }
        // Python: return await self.find()
        Box::pin(self._find()).await
    }

    /// Python: async def _handle_found_values(self, values)
    async fn _handle_found_values(mut self, values: Vec<Vec<u8>>) -> Option<Vec<u8>> {
        // Python: Counter(values).most_common(1)[0][0]
        let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
        for v in &values {
            *counts.entry(v.clone()).or_insert(0) += 1;
        }
        if counts.len() != 1 {
            log::warn!("Got multiple values for key {:?}", self.base.node.long_id);
        }
        let value = counts.into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(v, _)| v)?;

        // Python: peer = self.nearest_without_value.popleft()
        //         if peer: await self.protocol.call_store(peer, self.node.id, value)
        if let Some(peer) = self.nearest_without_value.popleft() {
            self.base.protocol.call_store(&peer, self.base.node.id, value.clone()).await;
        }

        Some(value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeSpiderCrawl
// ─────────────────────────────────────────────────────────────────────────────

/// Python: class NodeSpiderCrawl(SpiderCrawl)
pub struct NodeSpiderCrawl<P: SpiderProtocol> {
    pub base: SpiderCrawl<P>,
}

impl<P: SpiderProtocol + 'static> NodeSpiderCrawl<P> {
    pub fn new(protocol: Arc<P>, node: Node, peers: Vec<Node>, ksize: usize, alpha: usize) -> Self {
        Self { base: SpiderCrawl::new(protocol, node, peers, ksize, alpha) }
    }

    /// Python: async def find(self)
    pub async fn find(self) -> Vec<Node> {
        self._find().await
    }

    async fn _find(mut self) -> Vec<Node> {
        let responses = self.base.find_round(|proto, peer, node| async move {
            proto.call_find_node(&peer, &node).await
        }).await;
        self._nodes_found(responses).await
    }

    /// Python: async def _nodes_found(self, responses)
    async fn _nodes_found(
        mut self,
        responses: HashMap<[u8; ID_LEN], RawResponse>,
    ) -> Vec<Node> {
        let mut toremove: Vec<[u8; ID_LEN]> = vec![];

        for (peerid, response) in &responses {
            let r = RPCFindResponse::new(response.clone());
            if !r.happened() {
                toremove.push(*peerid);
            } else {
                self.base.nearest.push(r.get_node_list());
            }
        }
        self.base.nearest.remove(&toremove);

        if self.base.nearest.have_contacted_all() {
            // Python: return list(self.nearest)
            return self.base.nearest.to_vec();
        }
        Box::pin(self._find()).await
    }
}
