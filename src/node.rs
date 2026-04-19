/// Exact translation of node.py
///
/// Node: encapsulates node_id (20 bytes), ip, port, long_id (u128 XOR space)
/// NodeHeap: a max-size min-heap ordered by XOR distance from a pivot node
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet};
use std::fmt;

use crate::utils::ID_LEN;

// ─────────────────────────────────────────────────────────────────────────────
// Node
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Node {
    pub id: [u8; ID_LEN],   // raw 20-byte node id
    pub ip: Option<String>,
    pub port: Option<u16>,
    pub long_id: u128,      // id interpreted as big-endian integer (for XOR distance)
}

impl Node {
    /// Python: Node(node_id, ip=None, port=None)
    pub fn new(id: [u8; ID_LEN], ip: Option<String>, port: Option<u16>) -> Self {
        let long_id = Self::bytes_to_u128(&id);
        Self { id, ip, port, long_id }
    }

    pub fn from_id(id: [u8; ID_LEN]) -> Self {
        Self::new(id, None, None)
    }

    pub fn random() -> Self {
        use rand::RngCore;
        let mut id = [0u8; ID_LEN];
        rand::thread_rng().fill_bytes(&mut id);
        Self::from_id(id)
    }

    fn bytes_to_u128(id: &[u8; ID_LEN]) -> u128 {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&id[4..20]);
        u128::from_be_bytes(buf)
    }

    /// Python: node.same_home_as(other)
    pub fn same_home_as(&self, other: &Node) -> bool {
        self.ip == other.ip && self.port == other.port
    }

    /// Python: node.distance_to(other) → self.long_id ^ other.long_id
    pub fn distance_to(&self, other: &Node) -> u128 {
        self.long_id ^ other.long_id
    }

    pub fn address(&self) -> Option<(String, u16)> {
        match (&self.ip, self.port) {
            (Some(ip), Some(port)) => Some((ip.clone(), port)),
            _ => None,
        }
    }
}

impl fmt::Display for Node {
    /// Python: "%s:%s" % (self.ip, str(self.port))
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", 
            self.ip.as_deref().unwrap_or("None"),
            self.port.map_or("None".to_string(), |p| p.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeHeap — min-heap by XOR distance, capped at maxsize
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct HeapEntry {
    distance: u128,
    node: Node,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.distance == other.distance && self.node.id == other.node.id
    }
}
impl Eq for HeapEntry {}

/// Min-heap: smallest distance = highest priority (Reverse order)
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.distance.cmp(&self.distance)
            .then(other.node.id.cmp(&self.node.id))
    }
}

#[derive(Debug, Clone)]
pub struct NodeHeap {
    pub node: Node,
    heap: BinaryHeap<HeapEntry>,
    pub contacted: HashSet<[u8; ID_LEN]>,
    pub maxsize: usize,
}

impl NodeHeap {
    /// Python: NodeHeap(node, maxsize)
    pub fn new(node: Node, maxsize: usize) -> Self {
        Self {
            node,
            heap: BinaryHeap::new(),
            contacted: HashSet::new(),
            maxsize,
        }
    }

    /// Python: heap.remove(peers) — peers is a list of node ids
    pub fn remove(&mut self, peers: &[[u8; ID_LEN]]) {
        if peers.is_empty() {
            return;
        }
        let peer_set: HashSet<[u8; ID_LEN]> = peers.iter().cloned().collect();
        let remaining: Vec<HeapEntry> = self.heap.drain()
            .filter(|e| !peer_set.contains(&e.node.id))
            .collect();
        self.heap = remaining.into_iter().collect();
    }

    /// Python: heap.get_node(node_id)
    pub fn get_node(&self, node_id: &[u8; ID_LEN]) -> Option<Node> {
        self.heap.iter()
            .find(|e| &e.node.id == node_id)
            .map(|e| e.node.clone())
    }

    /// Python: heap.have_contacted_all()
    pub fn have_contacted_all(&self) -> bool {
        self.get_uncontacted().is_empty()
    }

    /// Python: heap.get_ids()
    pub fn get_ids(&self) -> Vec<[u8; ID_LEN]> {
        self.iter().map(|n| n.id).collect()
    }

    /// Python: heap.mark_contacted(node)
    pub fn mark_contacted(&mut self, node: &Node) {
        self.contacted.insert(node.id);
    }

    /// Python: heap.popleft() — pop the single closest node
    pub fn popleft(&mut self) -> Option<Node> {
        self.heap.pop().map(|e| e.node)
    }

    /// Python: heap.push(nodes) — nodes can be a single Node or a list
    pub fn push(&mut self, nodes: Vec<Node>) {
        for node in nodes {
            if !self.contains(&node) {
                let distance = self.node.distance_to(&node);
                self.heap.push(HeapEntry { distance, node });
            }
        }
    }

    pub fn push_one(&mut self, node: Node) {
        self.push(vec![node]);
    }

    /// Python: node in heap
    pub fn contains(&self, node: &Node) -> bool {
        self.heap.iter().any(|e| e.node.id == node.id)
    }

    /// Python: __len__ → min(len(heap), maxsize)
    pub fn len(&self) -> usize {
        self.heap.len().min(self.maxsize)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Python: __iter__ → heapq.nsmallest(maxsize, heap)
    /// Returns the maxsize closest nodes in ascending distance order.
    pub fn iter(&self) -> impl Iterator<Item = Node> {
        let mut entries: Vec<&HeapEntry> = self.heap.iter().collect();
        entries.sort_by_key(|e| e.distance);
        entries.into_iter()
            .take(self.maxsize)
            .map(|e| e.node.clone())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Python: heap.get_uncontacted()
    pub fn get_uncontacted(&self) -> Vec<Node> {
        self.iter()
            .filter(|n| !self.contacted.contains(&n.id))
            .collect()
    }

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
