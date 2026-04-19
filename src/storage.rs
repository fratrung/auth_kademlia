/// Exact translation of storage.py
///
/// IStorage trait + ForgetfulStorage with TTL-based culling.
/// Uses an IndexMap to maintain insertion order (like Python's OrderedDict).
use std::time::{Duration, Instant};
use indexmap::IndexMap;

pub const DEFAULT_TTL: i64 = 604_800; // one week in seconds

// ─────────────────────────────────────────────────────────────────────────────
// IStorage trait  (abstract base class in Python)
// ─────────────────────────────────────────────────────────────────────────────

pub trait IStorage: Send + Sync {
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>);
    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>>;
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_default(key, None)
    }
    fn delete(&mut self, key: &[u8]);
    /// Returns (key, value) pairs older than seconds_old
    fn iter_older_than(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)>;
    /// Iterate all non-expired (key, value) pairs
    fn iter_all(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
}

// ─────────────────────────────────────────────────────────────────────────────
// StorageEntry — internal value + timestamp
// ─────────────────────────────────────────────────────────────────────────────

struct StorageEntry {
    value: Vec<u8>,
    inserted_at: Instant,
}

// ─────────────────────────────────────────────────────────────────────────────
// ForgetfulStorage
// ─────────────────────────────────────────────────────────────────────────────

/// Python: ForgetfulStorage(ttl=604800)
/// ttl = -1 means no expiry (like Python's ttl = -1 special case used in AuthKademlia)
pub struct ForgetfulStorage {
    /// Ordered by insertion time (IndexMap preserves insertion order like OrderedDict)
    pub data: IndexMap<Vec<u8>, StorageEntry>,
    pub ttl: i64,
}

impl ForgetfulStorage {
    pub fn new(ttl: i64) -> Self {
        Self {
            data: IndexMap::new(),
            ttl,
        }
    }

    /// Python: __setitem__ — re-inserts key to update position (like del + insert)
    pub fn set_item(&mut self, key: Vec<u8>, value: Vec<u8>) {
        // Remove existing entry first (to update insertion order, like Python)
        self.data.swap_remove(&key);
        self.data.insert(key, StorageEntry {
            value,
            inserted_at: Instant::now(),
        });
        self.cull();
    }

    /// Python: cull() — remove entries older than ttl
    pub fn cull(&mut self) {
        if self.ttl == -1 {
            return; // no TTL
        }
        // iter_older_than returns the stale keys; we pop them from the front
        // (OrderedDict popitem(last=False) = remove the oldest = first inserted)
        let ttl = self.ttl as u64;
        let threshold = Duration::from_secs(ttl);
        // collect keys to remove (oldest first)
        let to_remove: Vec<Vec<u8>> = self.data.iter()
            .filter(|(_, e)| e.inserted_at.elapsed() > threshold)
            .map(|(k, _)| k.clone())
            .collect();
        for k in to_remove {
            self.data.swap_remove(&k);
        }
    }

    /// Python: storage.delete(key)
    pub fn delete_key(&mut self, key: &[u8]) {
        self.cull();
        self.data.swap_remove(key);
    }

    /// Python: __getitem__ — returns just the value (panics if missing)
    pub fn get_item(&self, key: &[u8]) -> &Vec<u8> {
        &self.data.get(key).expect("key not found").value
    }

    /// Python: __repr__
    pub fn repr(&self) -> String {
        format!("{:?}", self.data.keys().collect::<Vec<_>>())
    }

    /// Python: iter_older_than(seconds_old)
    /// Returns (key, value) for entries inserted more than seconds_old seconds ago
    pub fn iter_older_than_secs(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let threshold = Duration::from_secs(seconds_old);
        // Python uses takewhile on insertion-order, stopping at first non-stale entry
        // We replicate this: iterate in insertion order, take while stale
        self.data.iter()
            .take_while(|(_, e)| e.inserted_at.elapsed() >= threshold)
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect()
    }
}

impl IStorage for ForgetfulStorage {
    /// Python: storage[key] = value  (__setitem__)
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.set_item(key, value);
    }

    /// Python: storage.get(key, default=None)
    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>> {
        // Note: we don't call cull here because &self is immutable.
        // In Python, get() calls cull(). We cull on write to keep the same effect.
        self.data.get(key).map(|e| e.value.clone()).or(default)
    }

    fn delete(&mut self, key: &[u8]) {
        self.delete_key(key);
    }

    fn iter_older_than(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.iter_older_than_secs(seconds_old)
    }

    /// Python: __iter__ → yields (key, value) pairs (non-expired)
    fn iter_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let threshold = if self.ttl == -1 {
            None
        } else {
            Some(Duration::from_secs(self.ttl as u64))
        };
        self.data.iter()
            .filter(|(_, e)| {
                threshold.map_or(true, |t| e.inserted_at.elapsed() <= t)
            })
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect()
    }
}
