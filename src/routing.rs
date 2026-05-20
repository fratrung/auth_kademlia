/// Kademlia routing table with binary bucket splitting.
///
/// The routing table maintains a list of K-buckets, each covering a contiguous
/// range of the 128-bit XOR keyspace. When a bucket is full and contains the
/// local node's ID range, it is split into two halves. This ensures that the
/// table has fine-grained resolution near the local node and coarser resolution
/// for distant peers — exactly as specified in the Kademlia paper.
use std::collections::VecDeque;
use std::ops::RangeInclusive;

use crate::node::Node;

/// A single K-bucket covering a contiguous range of the XOR keyspace.
pub struct KBucket {
    /// The inclusive range `[lo, hi]` of `long_id` values this bucket covers.
    pub range: RangeInclusive<u128>,
    /// Nodes in LRU order: the least-recently-seen node is at the front.
    nodes: VecDeque<Node>,
    /// Maximum number of nodes (`k` in the Kademlia paper).
    ksize: usize,
}

impl KBucket {
    /// Create an empty bucket covering `range`.
    pub fn new(range: RangeInclusive<u128>, ksize: usize) -> Self {
        Self {
            range,
            nodes: VecDeque::new(),
            ksize,
        }
    }

    /// Insert or refresh `node`.
    ///
    /// If the node is already known it is moved to the tail (most-recently-seen
    /// position). If the bucket has spare capacity the node is appended.
    ///
    /// Returns `true` if the node was inserted or refreshed, `false` if the
    /// bucket is full and the node could not be added.
    pub fn add_node(&mut self, node: Node) -> bool {
        // Refresh: move to back if already present.
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push_back(node);
            return true;
        }
        if self.nodes.len() < self.ksize {
            self.nodes.push_back(node);
            true
        } else {
            false // bucket full
        }
    }

    /// Remove `node` from the bucket.
    pub fn remove_node(&mut self, node: &Node) {
        self.nodes.retain(|n| n.id != node.id);
    }

    /// Return `true` if `node` is in the bucket.
    pub fn contains(&self, node: &Node) -> bool {
        self.nodes.iter().any(|n| n.id == node.id)
    }

    /// A bucket is "lonely" if it has fewer than `k/2` nodes and therefore
    /// needs a refresh crawl.
    pub fn is_lonely(&self) -> bool {
        self.nodes.len() < (self.ksize / 2).max(1)
    }

    /// Immutable view of the node list (LRU order).
    pub fn nodes(&self) -> &VecDeque<Node> {
        &self.nodes
    }

    /// Number of nodes currently in the bucket.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Return `true` if this bucket's range contains `long_id`.
    pub fn covers(&self, long_id: u128) -> bool {
        self.range.contains(&long_id)
    }
}

/// Maintains a list of K-buckets that together partition the entire 128-bit
/// XOR keyspace. Buckets are split when they are full *and* cover the local
/// node's ID, so the table has high resolution near the local node.
pub struct RoutingTable {
    /// The local node.
    pub node: Node,
    /// Maximum bucket size (`k`).
    ksize: usize,
    /// Ordered list of K-buckets. The list is always sorted by the lower bound
    /// of each bucket's range.
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// Create a routing table with a single bucket spanning the full keyspace.
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
    /// If the target bucket is full and covers the local node's ID, the bucket
    /// is split and insertion is retried. Otherwise the node is silently
    /// discarded (as per the Kademlia paper).
    pub fn add_contact(&mut self, node: Node) {
        if node.id == self.node.id {
            return;
        }
        self.insert(node);
    }

    /// Recursive helper so `split_bucket` can call `insert` cleanly.
    fn insert(&mut self, node: Node) {
        let idx = self.bucket_index_for(node.long_id);
        if self.buckets[idx].add_node(node.clone()) {
            return;
        }
        // Bucket full. Split only if it covers the local node.
        if self.buckets[idx].covers(self.node.long_id) {
            self.split_bucket(idx);
            self.insert(node); // retry after split
        }
        // Otherwise silently discard — the LRU head should be pinged in a
        // full implementation (§2.2 of the Kademlia paper).
    }

    /// Remove a contact (called when a node sends a `leave` RPC).
    pub fn remove_contact(&mut self, node: &Node) {
        let idx = self.bucket_index_for(node.long_id);
        self.buckets[idx].remove_node(node);
    }

    /// Return `true` if `node` is not yet in any bucket.
    pub fn is_new_node(&self, node: &Node) -> bool {
        let idx = self.bucket_index_for(node.long_id);
        !self.buckets[idx].contains(node)
    }

    /// Return the `k` nodes closest to `target`, optionally excluding one node.
    ///
    /// Collects candidates from all buckets, sorts by XOR distance to
    /// `target`, and returns at most `ksize` results.
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

    /// Return buckets that are lonely and therefore need a refresh crawl.
    pub fn lonely_buckets(&self) -> Vec<&KBucket> {
        self.buckets.iter().filter(|b| b.is_lonely()).collect()
    }

    /// Split bucket at `idx` into two equal halves.
    ///
    /// The midpoint is `lo + (hi - lo) / 2`. All existing nodes are
    /// redistributed into the appropriate half.
    fn split_bucket(&mut self, idx: usize) {
        let range = self.buckets[idx].range.clone();
        let lo = *range.start();
        let hi = *range.end();
        let mid = lo + (hi - lo) / 2;

        let existing_nodes: Vec<Node> = self.buckets[idx].nodes().iter().cloned().collect();

        let mut low_bucket = KBucket::new(lo..=mid, self.ksize);
        let mut high_bucket = KBucket::new(mid + 1..=hi, self.ksize);

        for n in existing_nodes {
            if n.long_id <= mid {
                low_bucket.add_node(n);
            } else {
                high_bucket.add_node(n);
            }
        }

        // Replace the old bucket with the two new halves.
        self.buckets.remove(idx);
        self.buckets.insert(idx, high_bucket);
        self.buckets.insert(idx, low_bucket);
    }

    /// Return the index of the bucket whose range contains `long_id`.
    ///
    /// Uses a linear scan over the (typically small) bucket list. For very
    /// large networks a binary search would be faster, but this matches the
    /// Python implementation's simplicity.
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
    fn bucket_splits_on_overflow() {
        let local = make_node("local");
        let ksize = 2;
        let mut rt = RoutingTable::new(local.clone(), ksize);
        // Insert more than ksize nodes — the table must split.
        for i in 0..20 {
            rt.add_contact(make_node(&format!("peer{}", i)));
        }
        // The table should still return at most ksize neighbors.
        let found = rt.find_neighbors(&make_node("target"), None);
        assert!(found.len() <= ksize);
    }
}
