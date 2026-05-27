/// Kademlia routing table with binary bucket splitting.
///
/// Follows the Python AuthKademlia implementation strictly:
/// - KBucket has a primary `nodes` list and a `replacement_nodes` list (§4.1).
/// - Bucket splits when full AND (covers local node OR depth % 5 != 0) (§4.2).
/// - When split is not possible, the LRU head is returned to the caller for pinging.
/// - `remove_node` promotes from replacement_nodes automatically.
/// - Lonely buckets = not updated in the last hour (time-based, §2.3).
use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::time::Instant;

use crate::node::Node;

/// A single K-bucket covering a contiguous range of the XOR keyspace.
pub struct KBucket {
    /// The inclusive range `[lo, hi]` of `long_id` values this bucket covers.
    pub range: RangeInclusive<u128>,
    /// Primary node list in LRU order (least-recently-seen at front).
    nodes: VecDeque<Node>,
    /// Overflow list: nodes that arrived when the bucket was full (§4.1).
    replacement_nodes: VecDeque<Node>,
    /// Maximum number of primary nodes (`k`).
    ksize: usize,
    /// Cap on replacement list size (`k * 5`, matching Python default).
    max_replacement_nodes: usize,
    /// Timestamp of last successful add/refresh — used for lonely-bucket detection.
    last_updated: Instant,
}

impl KBucket {
    pub fn new(range: RangeInclusive<u128>, ksize: usize) -> Self {
        Self {
            range,
            nodes: VecDeque::new(),
            replacement_nodes: VecDeque::new(),
            ksize,
            max_replacement_nodes: ksize * 5,
            last_updated: Instant::now(),
        }
    }

    /// Insert or refresh `node`.
    ///
    /// - Already known → move to MRU tail, return `true`.
    /// - Bucket has capacity → append, return `true`.
    /// - Bucket full → add to replacement list (capped), return `false`.
    pub fn add_node(&mut self, node: Node) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push_back(node);
            self.last_updated = Instant::now();
            return true;
        }
        if self.nodes.len() < self.ksize {
            self.nodes.push_back(node);
            self.last_updated = Instant::now();
            return true;
        }
        // Bucket full: refresh position in replacement list if already there,
        // otherwise append. Cap at max_replacement_nodes (evict oldest).
        if let Some(pos) = self.replacement_nodes.iter().position(|n| n.id == node.id) {
            self.replacement_nodes.remove(pos);
        }
        self.replacement_nodes.push_back(node);
        while self.replacement_nodes.len() > self.max_replacement_nodes {
            self.replacement_nodes.pop_front();
        }
        false
    }

    /// Remove `node` from the primary list. If a replacement node is available,
    /// it is promoted automatically (§4.1).
    pub fn remove_node(&mut self, node: &Node) {
        self.replacement_nodes.retain(|n| n.id != node.id);
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            if let Some(replacement) = self.replacement_nodes.pop_back() {
                self.nodes.push_back(replacement);
            }
        }
    }

    /// Return `true` if `node` is in the primary list.
    pub fn contains(&self, node: &Node) -> bool {
        self.nodes.iter().any(|n| n.id == node.id)
    }

    /// Split this bucket at its midpoint into two new buckets.
    /// Both primary nodes and replacement nodes are redistributed (matches Python).
    pub fn split(self) -> (KBucket, KBucket) {
        let lo = *self.range.start();
        let hi = *self.range.end();
        let mid = lo + (hi - lo) / 2;

        let mut low = KBucket::new(lo..=mid, self.ksize);
        let mut high = KBucket::new(mid + 1..=hi, self.ksize);

        for n in self.nodes.into_iter().chain(self.replacement_nodes) {
            if n.long_id <= mid {
                low.add_node(n);
            } else {
                high.add_node(n);
            }
        }
        (low, high)
    }

    /// Length of the shared binary prefix (in bits) of all primary node IDs.
    /// Used by the §4.2 split condition: also split when depth % 5 != 0.
    pub fn depth(&self) -> usize {
        if self.nodes.len() < 2 {
            return if self.nodes.is_empty() {
                0
            } else {
                self.nodes[0].id.len() * 8
            };
        }
        let first = &self.nodes[0].id;
        let mut prefix_len = 0;
        'outer: for (byte_idx, &byte) in first.iter().enumerate() {
            for shift in (0..8).rev() {
                let bit = (byte >> shift) & 1;
                for node in self.nodes.iter().skip(1) {
                    if ((node.id[byte_idx] >> shift) & 1) != bit {
                        break 'outer;
                    }
                }
                prefix_len += 1;
            }
        }
        prefix_len
    }

    /// A bucket is "lonely" if it hasn't been updated in the last hour (§2.3).
    pub fn is_lonely(&self) -> bool {
        self.last_updated.elapsed().as_secs() > 3600
    }

    /// Least-recently-seen node (LRU head). Caller should ping it when the
    /// bucket is full and cannot be split (§4.2).
    pub fn head(&self) -> Option<&Node> {
        self.nodes.front()
    }

    /// Immutable view of the primary node list (LRU order).
    pub fn nodes(&self) -> &VecDeque<Node> {
        &self.nodes
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn covers(&self, long_id: u128) -> bool {
        self.range.contains(&long_id)
    }
}

/// Maintains a list of K-buckets that together partition the entire 128-bit
/// XOR keyspace.
pub struct RoutingTable {
    pub node: Node,
    ksize: usize,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(node: Node, ksize: usize) -> Self {
        let bucket = KBucket::new(0..=u128::MAX, ksize);
        Self {
            node,
            ksize,
            buckets: vec![bucket],
        }
    }

    /// Add a contact to the routing table.
    ///
    /// Returns `Some(lru_node)` when the target bucket is full and cannot be
    /// split. The caller is responsible for pinging `lru_node` and evicting it
    /// via `remove_contact` if it does not respond (§4.2).
    pub fn add_contact(&mut self, node: Node) -> Option<Node> {
        if node.id == self.node.id {
            return None;
        }
        self.insert(node)
    }

    fn insert(&mut self, node: Node) -> Option<Node> {
        let idx = self.bucket_index_for(node.long_id);
        if self.buckets[idx].add_node(node.clone()) {
            return None;
        }
        // §4.2: split if bucket covers local node OR if depth % 5 != 0.
        if self.buckets[idx].covers(self.node.long_id)
            || !self.buckets[idx].depth().is_multiple_of(5)
        {
            self.split_bucket(idx);
            return self.insert(node);
        }
        // Cannot split: return LRU head so the caller can ping it.
        self.buckets[idx].head().cloned()
    }

    pub fn remove_contact(&mut self, node: &Node) {
        let idx = self.bucket_index_for(node.long_id);
        self.buckets[idx].remove_node(node);
    }

    pub fn is_new_node(&self, node: &Node) -> bool {
        let idx = self.bucket_index_for(node.long_id);
        !self.buckets[idx].contains(node)
    }

    /// Return the `k` nodes closest to `target`, optionally excluding one node.
    pub fn find_neighbors(&self, target: &Node, exclude: Option<&Node>) -> Vec<Node> {
        let mut candidates: Vec<Node> = self
            .buckets
            .iter()
            .flat_map(|b| b.nodes().iter().cloned())
            .filter(|n| exclude.is_none_or(|ex| n.id != ex.id))
            .collect();

        candidates.sort_unstable_by_key(|n| n.distance_to(target));
        candidates.truncate(self.ksize);
        candidates
    }

    pub fn lonely_buckets(&self) -> Vec<&KBucket> {
        self.buckets.iter().filter(|b| b.is_lonely()).collect()
    }

    /// Split the bucket at `idx` using `KBucket::split()`, which distributes
    /// both primary nodes and replacement nodes into the two halves.
    fn split_bucket(&mut self, idx: usize) {
        let bucket = self.buckets.remove(idx);
        let (low, high) = bucket.split();
        self.buckets.insert(idx, high);
        self.buckets.insert(idx, low);
    }

    fn bucket_index_for(&self, long_id: u128) -> usize {
        self.buckets
            .iter()
            .position(|b| b.covers(long_id))
            .unwrap_or(self.buckets.len() - 1)
    }

    pub fn buckets(&self) -> &Vec<KBucket> {
        &self.buckets
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
    fn add_and_find() {
        let local = make_node("local");
        let mut rt = RoutingTable::new(local.clone(), 3);
        let peer = make_node("peer");
        rt.add_contact(peer.clone());
        let found = rt.find_neighbors(&peer, None);
        assert!(!found.is_empty());
    }

    #[test]
    fn ignores_self() {
        let local = make_node("local");
        let mut rt = RoutingTable::new(local.clone(), 3);
        rt.add_contact(local.clone());
        let found = rt.find_neighbors(&local, None);
        assert!(!found.iter().any(|n| n.id == local.id));
    }

    #[test]
    fn remove_contact() {
        let local = make_node("local");
        let mut rt = RoutingTable::new(local.clone(), 20);
        let peer = make_node("peer");
        rt.add_contact(peer.clone());
        rt.remove_contact(&peer);
        assert!(rt.find_neighbors(&peer, None).is_empty());
    }

    #[test]
    fn replacement_node_promoted_on_eviction() {
        let local = make_node("local");
        let ksize = 1;
        let mut rt = RoutingTable::new(local.clone(), ksize);
        let peer_a = make_node("peer_a");
        let peer_b = make_node("peer_b");
        // Fill bucket with peer_a, then add peer_b to replacement list.
        rt.add_contact(peer_a.clone());
        rt.add_contact(peer_b.clone());
        // Remove peer_a — peer_b should be promoted.
        rt.remove_contact(&peer_a);
        let found = rt.find_neighbors(&make_node("target"), None);
        assert!(found.iter().any(|n| n.id == peer_b.id));
    }

    #[test]
    fn bucket_splits_on_overflow() {
        let local = make_node("local");
        let ksize = 2;
        let mut rt = RoutingTable::new(local.clone(), ksize);
        for i in 0..20 {
            rt.add_contact(make_node(&format!("peer{}", i)));
        }
        let found = rt.find_neighbors(&make_node("target"), None);
        assert!(found.len() <= ksize);
    }
}
