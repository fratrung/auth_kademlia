/// In-memory cache for signature verification results.
///
/// Keyed by SHA-256 of the full record bytes so that any byte-level change
/// (algorithm field, signature bytes, or payload) produces a cache miss and
/// forces a full cryptographic re-verification. The cache is bounded in size
/// and entries expire after one hour.
use moka::sync::Cache;
use sha2::{Digest, Sha256};
use std::time::Duration;

pub struct SignatureCache {
    cache: Cache<[u8; 32], bool>,
}

impl SignatureCache {
    pub fn new(max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(3600))
            .build();
        Self { cache }
    }

    fn cache_key(value: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(value);
        hasher.finalize().into()
    }

    pub fn get(&self, value: &[u8]) -> Option<bool> {
        self.cache.get(&Self::cache_key(value))
    }

    pub fn insert(&self, value: &[u8], result: bool) {
        self.cache.insert(Self::cache_key(value), result);
    }
}
