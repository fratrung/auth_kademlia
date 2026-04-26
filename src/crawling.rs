/// Iterative Kademlia lookup (spider crawl).
///
/// Implements the three-class crawl hierarchy from the original Python:
///
/// - `SpiderCrawl`       — shared crawl state and the `find_round` driver
/// - `ValueSpiderCrawl`  — lookup terminating when a value is found
/// - `NodeSpiderCrawl`   — lookup terminating when the k-closest nodes are found
use std::collections::HashMap;
use std::sync::Arc;

use async_recursion::async_recursion;
use log;

use crate::node::{Node, NodeHeap};
use crate::utils::ID_LEN;


/// Raw tuple returned by a protocol `call_find_*` method:
/// `(response_received, payload)`.
#[derive(Debug, Clone)]
pub struct RawResponse(pub bool, pub FindPayload);

/// The payload half of a `RawResponse`.
#[derive(Debug, Clone)]
pub enum FindPayload {
    /// A list of `(id_bytes, ip, port)` triples (find_node result or value miss).
    Nodes(Vec<(Vec<u8>, Option<String>, Option<u16>)>),
    /// A found value (find_value hit).
    Value(Vec<u8>),
    /// No response or a timeout.
    Empty,
}

pub struct RPCFindResponse {
    response: RawResponse,
}

impl RPCFindResponse {
    pub fn new(response: RawResponse) -> Self {
        Self { response }
    }

    pub fn happened(&self) -> bool {
        self.response.0
    }

    /// Did the response contain a value?
    pub fn has_value(&self) -> bool {
        matches!(self.response.1, FindPayload::Value(_))
    }

    /// Return the value, or `None` if the response did not contain one.
    pub fn get_value(&self) -> Option<Vec<u8>> {
        match &self.response.1 {
            FindPayload::Value(v) => Some(v.clone()),
            _ => None,
        }
    }

    /// Decode the node list from the payload.
    pub fn get_node_list(&self) -> Vec<Node> {
        match &self.response.1 {
            FindPayload::Nodes(tuples) => tuples
                .iter()
                .filter_map(|(id_bytes, ip, port)| {
                    if id_bytes.len() != ID_LEN {
                        return None;
                    }
                    let mut id = [0u8; ID_LEN];
                    id.copy_from_slice(id_bytes);
                    Some(Node::new(id, ip.clone(), *port))
                })
                .collect(),
            _ => vec![],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SpiderProtocol — dependency-injection interface
// ─────────────────────────────────────────────────────────────────────────────

/// The subset of the Kademlia protocol needed by the spider crawl.
///
/// This trait is implemented by `KademliaProtocol` and can be mocked in tests.
#[async_trait::async_trait]
pub trait SpiderProtocol: Send + Sync {
    async fn call_find_node(&self, peer: &Node, target: &Node) -> RawResponse;
    async fn call_find_value(&self, peer: &Node, target: &Node) -> RawResponse;
    async fn call_store(&self, peer: &Node, key: [u8; ID_LEN], value: Vec<u8>) -> bool;
}

// ─────────────────────────────────────────────────────────────────────────────
// SpiderCrawl — shared state and round driver
// ─────────────────────────────────────────────────────────────────────────────

/// Shared state for iterative Kademlia lookups.
pub struct SpiderCrawl<P: SpiderProtocol> {
    pub protocol: Arc<P>,
    pub ksize: usize,
    pub alpha: usize,
    /// The target key we are searching for.
    pub node: Node,
    /// The k closest known nodes to `node`, with contact tracking.
    pub nearest: NodeHeap,
    /// IDs seen in the previous round, used to detect convergence.
    pub last_ids_crawled: Vec<[u8; ID_LEN]>,
}

impl<P: SpiderProtocol> SpiderCrawl<P> {
    pub fn new(
        protocol: Arc<P>,
        node: Node,
        peers: Vec<Node>,
        ksize: usize,
        alpha: usize,
    ) -> Self {
        let mut nearest = NodeHeap::new(node.clone(), ksize);
        log::info!(
            "Creating spider crawl for {} with {} initial peers",
            node,
            peers.len()
        );
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

    /// Execute one round of the iterative lookup.
    ///
    /// Contacts up to `alpha` uncontacted nearest nodes concurrently using
    /// `rpcmethod`. Returns a map from peer ID to raw response.
    ///
    /// When the nearest set has not changed since the last round (convergence),
    /// *all* remaining uncontacted nodes are queried instead of just `alpha`.
    pub async fn find_round<F, Fut>(
        &mut self,
        rpcmethod: F,
    ) -> HashMap<[u8; ID_LEN], RawResponse>
    where
        F: Fn(Arc<P>, Node, Node) -> Fut + Clone,
        Fut: std::future::Future<Output = RawResponse> + Send,
    {
        log::info!("Crawling with nearest: {}", self.nearest);

        let current_ids = self.nearest.get_ids();
        let count = if current_ids == self.last_ids_crawled {
            // Converged: query everyone still uncontacted.
            self.nearest.len()
        } else {
            self.alpha
        };
        self.last_ids_crawled = current_ids;

        let uncontacted: Vec<Node> = self
            .nearest
            .get_uncontacted()
            .into_iter()
            .take(count)
            .collect();

        // Fire all RPCs concurrently.
        let mut futs: Vec<_> = Vec::with_capacity(uncontacted.len());
        for peer in &uncontacted {
            self.nearest.mark_contacted(peer);
            let proto = Arc::clone(&self.protocol);
            let peer_clone = peer.clone();
            let node_clone = self.node.clone();
            let f = rpcmethod.clone();
            let id = peer.id;
            futs.push(async move { (id, f(proto, peer_clone, node_clone).await) });
        }

        futures::future::join_all(futs)
            .await
            .into_iter()
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ValueSpiderCrawl
// ─────────────────────────────────────────────────────────────────────────────

/// Iterative lookup that terminates when a value is found or the network is
/// exhausted.
pub struct ValueSpiderCrawl<P: SpiderProtocol> {
    pub base: SpiderCrawl<P>,
    /// The single nearest node that did *not* have the value (used for
    /// post-lookup caching).
    pub nearest_without_value: NodeHeap,
}

impl<P: SpiderProtocol + 'static> ValueSpiderCrawl<P> {
    pub fn new(
        protocol: Arc<P>,
        node: Node,
        peers: Vec<Node>,
        ksize: usize,
        alpha: usize,
    ) -> Self {
        let nearest_without_value = NodeHeap::new(node.clone(), 1);
        Self {
            base: SpiderCrawl::new(protocol, node, peers, ksize, alpha),
            nearest_without_value,
        }
    }

    /// Run the lookup and return the value if found.
    pub async fn find(self) -> Option<Vec<u8>> {
        self.find_inner().await
    }

    #[async_recursion]
    async fn find_inner(mut self) -> Option<Vec<u8>> {
        let responses = self
            .base
            .find_round(|proto, peer, node| async move {
                proto.call_find_value(&peer, &node).await
            })
            .await;
        self.nodes_found(responses).await
    }

    #[async_recursion]
    async fn nodes_found(
        mut self,
        responses: HashMap<[u8; ID_LEN], RawResponse>,
    ) -> Option<Vec<u8>> {
        let mut to_remove: Vec<[u8; ID_LEN]> = vec![];
        let mut found_values: Vec<Vec<u8>> = vec![];

        for (peer_id, raw) in &responses {
            let r = RPCFindResponse::new(raw.clone());
            if !r.happened() {
                to_remove.push(*peer_id);
            } else if r.has_value() {
                if let Some(v) = r.get_value() {
                    found_values.push(v);
                }
            } else {
                // The peer didn't have the value — record it for caching later.
                if let Some(peer) = self.base.nearest.get_node(peer_id) {
                    self.nearest_without_value.push_one(peer);
                }
                self.base.nearest.push(r.get_node_list());
            }
        }
        self.base.nearest.remove(&to_remove);

        if !found_values.is_empty() {
            return self.handle_found_values(found_values).await;
        }
        if self.base.nearest.have_contacted_all() {
            return None; // not found
        }
        self.find_inner().await
    }

    /// Pick the most common value, store it on the nearest node that was
    /// missing it, and return it.
    async fn handle_found_values(mut self, values: Vec<Vec<u8>>) -> Option<Vec<u8>> {
        let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
        for v in &values {
            *counts.entry(v.clone()).or_insert(0) += 1;
        }
        if counts.len() > 1 {
            log::warn!(
                "Multiple distinct values found for key {:?} — returning majority",
                self.base.node.long_id
            );
        }
        let value = counts.into_iter().max_by_key(|(_, c)| *c).map(|(v, _)| v)?;

        // Kademlia § 2.3: store the value on the nearest node that missed it.
        if let Some(peer) = self.nearest_without_value.popleft() {
            self.base
                .protocol
                .call_store(&peer, self.base.node.id, value.clone())
                .await;
        }

        Some(value)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeSpiderCrawl
// ─────────────────────────────────────────────────────────────────────────────

/// Iterative lookup that returns the k closest nodes to a target.
pub struct NodeSpiderCrawl<P: SpiderProtocol> {
    pub base: SpiderCrawl<P>,
}

impl<P: SpiderProtocol + 'static> NodeSpiderCrawl<P> {
    pub fn new(
        protocol: Arc<P>,
        node: Node,
        peers: Vec<Node>,
        ksize: usize,
        alpha: usize,
    ) -> Self {
        Self { base: SpiderCrawl::new(protocol, node, peers, ksize, alpha) }
    }

    /// Run the lookup and return the k closest nodes found.
    pub async fn find(self) -> Vec<Node> {
        self.find_inner().await
    }

    #[async_recursion]
    async fn find_inner(mut self) -> Vec<Node> {
        let responses = self
            .base
            .find_round(|proto, peer, node| async move {
                proto.call_find_node(&peer, &node).await
            })
            .await;
        self.nodes_found(responses).await
    }

    #[async_recursion]
    async fn nodes_found(
        mut self,
        responses: HashMap<[u8; ID_LEN], RawResponse>,
    ) -> Vec<Node> {
        let mut to_remove: Vec<[u8; ID_LEN]> = vec![];

        for (peer_id, raw) in &responses {
            let r = RPCFindResponse::new(raw.clone());
            if !r.happened() {
                to_remove.push(*peer_id);
            } else {
                self.base.nearest.push(r.get_node_list());
            }
        }
        self.base.nearest.remove(&to_remove);

        if self.base.nearest.have_contacted_all() {
            return self.base.nearest.to_vec();
        }
        self.find_inner().await
    }
}
