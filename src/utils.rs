/// General catchall for functions that don't make sense as methods.
/// Exact translation of utils.py
use sha1::{Sha1, Digest};
use std::collections::HashMap;
use std::future::Future;
// use std::pin::Pin;

pub const ID_LEN: usize = 20;

/// sha1(string) — if string is not bytes, encode as utf-8 first.
/// Equivalent to Python's digest()
pub fn digest(string: &str) -> [u8; ID_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(string.as_bytes());
    hasher.finalize().into()
}

/// sha1(bytes) variant
pub fn digest_bytes(data: &[u8]) -> [u8; ID_LEN] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Equivalent to Python's gather_dict:
///   async def gather_dict(dic): ...
///   Runs all futures concurrently, returns HashMap<K, V>
///
/// Usage:
///   let mut map: HashMap<[u8;20], BoxFuture<...>> = HashMap::new();
///   let results = gather_dict(map).await;
pub async fn gather_dict<K, V, Fut>(dic: HashMap<K, Fut>) -> HashMap<K, V>
where
    K: Eq + std::hash::Hash + Clone + Send + 'static,
    V: Send + 'static,
    Fut: Future<Output = V> + Send + 'static,
{
    let keys: Vec<K> = dic.keys().cloned().collect();
    let futs: Vec<Fut> = dic.into_values().collect();

    let results = futures::future::join_all(futs).await;

    keys.into_iter().zip(results).collect()
}

/// Find the shared prefix between byte slices.
/// Equivalent to Python's shared_prefix()
pub fn shared_prefix(args: &[&[u8]]) -> Vec<u8> {
    if args.is_empty() {
        return vec![];
    }
    let min_len = args.iter().map(|a| a.len()).min().unwrap_or(0);
    let mut i = 0;
    while i < min_len {
        let ch = args[0][i];
        if args.iter().any(|a| a[i] != ch) {
            break;
        }
        i += 1;
    }
    args[0][..i].to_vec()
}

/// Convert bytes to a bit string.
/// Equivalent to Python's bytes_to_bit_string()
pub fn bytes_to_bit_string(bytes: &[u8]) -> String {
    bytes.iter()
        .map(|b| format!("{:08b}", b))
        .collect()
}
