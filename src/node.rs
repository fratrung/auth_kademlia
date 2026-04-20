/// Node and NodeHeap — core Kademlia data structures.
///
/// `Node` represents a single peer identified by a 20-byte SHA-1 ID.
/// `NodeHeap` is a bounded min-heap ordered by XOR distance from a pivot node,
/// used during iterative lookups.
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::fmt;

use crate::utils::ID_LEN;

// ─────────────────────────────────────────────────────────────────────────────
// Node
// ─────────────────────────────────────────────────────────────────────────────

/// A Kademlia peer node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Node {
    /// Raw 20-byte node ID.
    pub id: [u8; ID_LEN],
    pub ip: Option<String>,
    pub port: Option<u16>,
    /// The node ID interpreted as a 160-bit unsigned integer for XOR distance
    /// calculations. Since `u128` holds only 128 bits we fold the 20-byte ID
    /// by XOR-ing the top 4 bytes into the high 32 bits of the u128, preserving
    /// all bits without loss.
    pub long_id: u128,
}

impl Node {
    /// Create a node with a known address.
    pub fn new(id: [u8; ID_LEN], ip: Option<String>, port: Option<u16>) -> Self {
        let long_id = Self::id_to_u128(&id);
        Self { id, ip, port, long_id }
    }

    /// Create a node without an address (used as a lookup key).
    pub fn from_id(id: [u8; ID_LEN]) -> Self {
        Self::new(id, None, None)
    }

    /// Create a node with a random ID.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; ID_LEN];
        rand::thread_rng().fill_bytes(&mut id);
        Self::from_id(id)
    }

    /// Fold a 20-byte ID into a u128 without discarding any bits.
    ///
    /// Layout: bytes [0..16] form the base u128 (big-endian), then bytes
    /// [16..20] are XOR-ed into the top 32 bits so no information is lost.
    fn id_to_u128(id: &[u8; ID_LEN]) -> u128 {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&id[..16]);
        let base = u128::from_be_bytes(buf);
        let tail = u32::from_be_bytes(id[16..20].try_into().unwrap()) as u128;
        base ^ (tail << 96)
    }

    /// XOR distance to another node (used for Kademlia routing).
    pub fn distance_to(&self, other: &Node) -> u128 {
        self.long_id ^ other.long_id
    }

    /// Returns `true` if both nodes share the same IP and port.
    pub fn same_home_as(&self, other: &Node) -> bool {
        self.ip == other.ip && self.port == other.port
    }

    /// Return the node's address as `(ip, port)` if both are known.
    pub fn address(&self) -> Option<(String, u16)> {
        match (&self.ip, self.port) {
            (Some(ip), Some(port)) => Some((ip.clone(), port)),
            _ => None,
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            self.ip.as_deref().unwrap_or("None"),
            self.port.map_or_else(|| "None".to_string(), |p| p.to_string())
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeHeap internals
// ─────────────────────────────────────────────────────────────────────────────

/// An entry in the heap, ordered by XOR distance (ascending).
///
/// `BinaryHeap` in Rust is a max-heap, so we invert the ordering so that the
/// *smallest* distance has the highest priority.
#[derive(Debug, Clone)]
struct HeapEntry {
    distance: u128,
    node: Node,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.node.id == other.node.id
    }
}
impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Inverted so that `BinaryHeap` (max-heap) behaves as a min-heap by distance.
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse distance: larger distance = lower priority
        other
            .distance
            .cmp(&self.distance)
            .then_with(|| other.node.id.cmp(&self.node.id))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeHeap
// ─────────────────────────────────────────────────────────────────────────────

/// A bounded min-heap of nodes ordered by XOR distance from a pivot node.
///
/// Kademlia lookups maintain a heap of the `k` closest known nodes. This
/// structure enforces the bound at insertion time and tracks which nodes have
/// already been contacted during a crawl.
#[derive(Debug, Clone)]
pub struct NodeHeap {
    /// The pivot node — all distances are relative to this.
    pub node: Node,
    heap: BinaryHeap<HeapEntry>,
    /// IDs of nodes that have been marked as contacted.
    pub contacted: HashSet<[u8; ID_LEN]>,
    /// Maximum number of nodes the heap may hold.
    pub maxsize: usize,
}

impl NodeHeap {
    /// Create an empty heap with the given pivot and capacity.
    pub fn new(node: Node, maxsize: usize) -> Self {
        Self {
            node,
            heap: BinaryHeap::new(),
            contacted: HashSet::new(),
            maxsize,
        }
    }

    // ── Insertion ────────────────────────────────────────────────────────────

    /// Insert a batch of nodes, ignoring duplicates.
    ///
    /// After insertion the heap is trimmed to `maxsize` keeping the closest
    /// nodes.
    pub fn push(&mut self, nodes: Vec<Node>) {
        for node in nodes {
            if !self.contains(&node) {
                let distance = self.node.distance_to(&node);
                self.heap.push(HeapEntry { distance, node });
            }
        }
        self.enforce_maxsize();
    }

    /// Insert a single node.
    pub fn push_one(&mut self, node: Node) {
        self.push(vec![node]);
    }

    /// Trim the heap to `maxsize`, dropping the farthest nodes.
    fn enforce_maxsize(&mut self) {
        if self.heap.len() <= self.maxsize {
            return;
        }
        // Drain, sort by distance ascending, keep only the closest maxsize.
        let mut entries: Vec<HeapEntry> = self.heap.drain().collect();
        entries.sort_unstable_by_key(|e| e.distance);
        entries.truncate(self.maxsize);
        self.heap = entries.into_iter().collect();
    }

    // ── Removal ──────────────────────────────────────────────────────────────

    /// Remove nodes by ID.
    pub fn remove(&mut self, peers: &[[u8; ID_LEN]]) {
        if peers.is_empty() {
            return;
        }
        let peer_set: HashSet<[u8; ID_LEN]> = peers.iter().cloned().collect();
        let remaining: Vec<HeapEntry> = self
            .heap
            .drain()
            .filter(|e| !peer_set.contains(&e.node.id))
            .collect();
        self.heap = remaining.into_iter().collect();
    }

    /// Pop and return the single closest node.
    pub fn popleft(&mut self) -> Option<Node> {
        self.heap.pop().map(|e| e.node)
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /// Return `true` if the node is already in the heap.
    pub fn contains(&self, node: &Node) -> bool {
        self.heap.iter().any(|e| e.node.id == node.id)
    }

    /// Look up a node by its raw ID.
    pub fn get_node(&self, node_id: &[u8; ID_LEN]) -> Option<Node> {
        self.heap
            .iter()
            .find(|e| &e.node.id == node_id)
            .map(|e| e.node.clone())
    }

    /// Return `true` if every node in the heap has been contacted.
    pub fn have_contacted_all(&self) -> bool {
        self.get_uncontacted().is_empty()
    }

    /// Return the IDs of all nodes currently in the heap (closest first).
    pub fn get_ids(&self) -> Vec<[u8; ID_LEN]> {
        self.iter().map(|n| n.id).collect()
    }

    /// Number of nodes in the heap (capped at `maxsize`).
    pub fn len(&self) -> usize {
        self.heap.len().min(self.maxsize)
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    // ── Contact tracking ─────────────────────────────────────────────────────

    /// Mark a node as contacted so it is excluded from future crawl rounds.
    pub fn mark_contacted(&mut self, node: &Node) {
        self.contacted.insert(node.id);
    }

    /// Return nodes that have not yet been contacted, in ascending distance order.
    pub fn get_uncontacted(&self) -> Vec<Node> {
        self.iter()
            .filter(|n| !self.contacted.contains(&n.id))
            .collect()
    }

    // ── Iteration ────────────────────────────────────────────────────────────

    /// Iterate over nodes in ascending XOR-distance order, limited to `maxsize`.
    pub fn iter(&self) -> impl Iterator<Item = Node> + '_ {
        let mut entries: Vec<&HeapEntry> = self.heap.iter().collect();
        entries.sort_unstable_by_key(|e| e.distance);
        entries
            .into_iter()
            .take(self.maxsize)
            .map(|e| e.node.clone())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Collect all nodes into a `Vec` (closest first).
    pub fn to_vec(&self) -> Vec<Node> {
        self.iter().collect()
    }
}

impl fmt::Display for NodeHeap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let nodes: Vec<String> = self.iter().map(|n| n.to_string()).collect();
        write!(f, "[{}]", nodes.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::digest;

    fn make_node(key: &str) -> Node {
        Node::from_id(digest(key))
    }

    #[test]
    fn heap_respects_maxsize() {
        let pivot = make_node("pivot");
        let mut heap = NodeHeap::new(pivot, 3);
        for i in 0..10 {
            heap.push_one(make_node(&i.to_string()));
        }
        assert!(heap.heap.len() <= 3);
    }

    #[test]
    fn heap_no_duplicates() {
        let pivot = make_node("pivot");
        let mut heap = NodeHeap::new(pivot, 10);
        let node = make_node("a");
        heap.push_one(node.clone());
        heap.push_one(node);
        assert_eq!(heap.heap.len(), 1);
    }

    #[test]
    fn contacted_tracking() {
        let pivot = make_node("pivot");
        let mut heap = NodeHeap::new(pivot, 10);
        let node = make_node("peer");
        heap.push_one(node.clone());
        assert!(!heap.have_contacted_all());
        heap.mark_contacted(&node);
        assert!(heap.have_contacted_all());
    }
}
