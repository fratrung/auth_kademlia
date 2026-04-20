/// Key-value storage with optional TTL-based expiry.
///
/// `IStorage` is the abstract interface used by the protocol layer.
/// `ForgetfulStorage` is the concrete implementation: an insertion-ordered
/// map (like Python's `OrderedDict`) that evicts entries older than a
/// configurable TTL on every write.
use indexmap::IndexMap;
use std::time::{Duration, Instant};

/// One week in seconds — the default TTL used in AuthKademlia.
pub const DEFAULT_TTL: i64 = 604_800;

// ─────────────────────────────────────────────────────────────────────────────
// IStorage trait
// ─────────────────────────────────────────────────────────────────────────────

/// Abstract key-value store interface.
///
/// Keys and values are raw byte vectors. Implementations must be `Send + Sync`
/// so they can be shared across async tasks behind a `Mutex`.
pub trait IStorage: Send + Sync {
    /// Insert or replace a key-value pair.
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>);

    /// Retrieve a value, returning `default` if the key is absent.
    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>>;

    /// Retrieve a value, returning `None` if the key is absent.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_default(key, None)
    }

    /// Remove a key.
    fn delete(&mut self, key: &[u8]);

    /// Return all `(key, value)` pairs whose insertion time is older than
    /// `seconds_old` seconds, in insertion order.
    fn iter_older_than(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)>;

    /// Return all non-expired `(key, value)` pairs in insertion order.
    fn iter_all(&self) -> Vec<(Vec<u8>, Vec<u8>)>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal entry
// ─────────────────────────────────────────────────────────────────────────────

struct StorageEntry {
    value: Vec<u8>,
    inserted_at: Instant,
}

impl StorageEntry {
    fn new(value: Vec<u8>) -> Self {
        Self { value, inserted_at: Instant::now() }
    }

    fn age(&self) -> Duration {
        self.inserted_at.elapsed()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ForgetfulStorage
// ─────────────────────────────────────────────────────────────────────────────

/// An insertion-ordered store that evicts entries older than `ttl` seconds.
///
/// A `ttl` of `-1` disables expiry entirely (entries are kept forever).
///
/// # Notes on culling
///
/// Culling (expiry) happens on every *write* operation. Read operations
/// (`get`, `iter_all`) do not cull, so an expired entry may still be
/// returned if no write has occurred since expiry. This mirrors the
/// original Python behaviour where `cull()` was called from `__setitem__`.
pub struct ForgetfulStorage {
    /// Insertion-ordered map. `IndexMap` preserves insertion order like
    /// Python's `OrderedDict`.
    data: IndexMap<Vec<u8>, StorageEntry>,
    /// Time-to-live in seconds. `-1` means no expiry.
    ttl: i64,
}

impl ForgetfulStorage {
    /// Create a new store with the given TTL.
    ///
    /// Pass `ttl = -1` to disable expiry.
    pub fn new(ttl: i64) -> Self {
        Self { data: IndexMap::new(), ttl }
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    /// Remove all entries that have exceeded the TTL.
    ///
    /// Iterates in insertion order and removes stale entries. Because
    /// `IndexMap` preserves insertion order and entries are always inserted
    /// at the end, the stale entries will cluster at the front — matching the
    /// Python `popitem(last=False)` pattern.
    fn cull(&mut self) {
        if self.ttl == -1 {
            return;
        }
        let threshold = Duration::from_secs(self.ttl as u64);
        // Collect keys of stale entries first (can't remove during iteration).
        let stale: Vec<Vec<u8>> = self
            .data
            .iter()
            .take_while(|(_, e)| e.age() > threshold)
            .map(|(k, _)| k.clone())
            .collect();
        for k in stale {
            self.data.swap_remove(&k);
        }
    }

    fn ttl_duration(&self) -> Option<Duration> {
        if self.ttl == -1 {
            None
        } else {
            Some(Duration::from_secs(self.ttl as u64))
        }
    }
}

impl IStorage for ForgetfulStorage {
    /// Insert or replace `key → value`.
    ///
    /// Re-inserting an existing key moves it to the back of the insertion
    /// order (matching Python's `del self[key]; self[key] = value` pattern),
    /// then culls expired entries.
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        // Remove existing entry to update its insertion timestamp and position.
        self.data.swap_remove(&key);
        self.data.insert(key, StorageEntry::new(value));
        self.cull();
    }

    fn get_default(&self, key: &[u8], default: Option<Vec<u8>>) -> Option<Vec<u8>> {
        self.data
            .get(key)
            .map(|e| e.value.clone())
            .or(default)
    }

    fn delete(&mut self, key: &[u8]) {
        self.cull();
        self.data.swap_remove(key);
    }

    /// Return `(key, value)` pairs inserted more than `seconds_old` seconds ago.
    ///
    /// Iterates in insertion order and stops at the first non-stale entry
    /// (matching Python's `takewhile`).
    fn iter_older_than(&self, seconds_old: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
        let threshold = Duration::from_secs(seconds_old);
        self.data
            .iter()
            .take_while(|(_, e)| e.age() >= threshold)
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect()
    }

    /// Return all non-expired `(key, value)` pairs.
    fn iter_all(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let threshold = self.ttl_duration();
        self.data
            .iter()
            .filter(|(_, e)| threshold.map_or(true, |t| e.age() <= t))
            .map(|(k, e)| (k.clone(), e.value.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn set_and_get() {
        let mut s = ForgetfulStorage::new(-1);
        s.set(b"key".to_vec(), b"value".to_vec());
        assert_eq!(s.get(b"key"), Some(b"value".to_vec()));
    }

    #[test]
    fn delete() {
        let mut s = ForgetfulStorage::new(-1);
        s.set(b"k".to_vec(), b"v".to_vec());
        s.delete(b"k");
        assert_eq!(s.get(b"k"), None);
    }

    #[test]
    fn ttl_expiry() {
        let mut s = ForgetfulStorage::new(1); // 1-second TTL
        s.set(b"k".to_vec(), b"v".to_vec());
        sleep(Duration::from_millis(1100));
        // Trigger cull via a write
        s.set(b"other".to_vec(), b"x".to_vec());
        assert_eq!(s.get(b"k"), None);
    }

    #[test]
    fn no_ttl_never_expires() {
        let mut s = ForgetfulStorage::new(-1);
        s.set(b"k".to_vec(), b"v".to_vec());
        sleep(Duration::from_millis(10));
        assert_eq!(s.get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn iter_older_than() {
        let mut s = ForgetfulStorage::new(-1);
        s.set(b"a".to_vec(), b"1".to_vec());
        sleep(Duration::from_millis(1100));
        s.set(b"b".to_vec(), b"2".to_vec());
        let old = s.iter_older_than(1);
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].0, b"a".to_vec());
    }
}
