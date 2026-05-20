# AuthKademlia-RS

A Rust reimplementation of [AuthKademlia](https://github.com/fratrung/AuthKademlia) — an extended Kademlia Distributed Hash Table with native support for **signed records** and **Verifiable Data Registry (VDR)** capabilities for Decentralized Identifiers (DIDs).

-----

## Overview

AuthKademlia-RS is a high-performance, asynchronous implementation of the [Kademlia DHT protocol](http://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf) written in Rust. It extends the standard Kademlia specification with cryptographic record signing, making it suitable for use as a decentralized identity infrastructure layer.

Unlike conventional DHT implementations, AuthKademlia-RS treats stored values as **verifiable artifacts**: each record is cryptographically bound to its author and can be independently verified by any node in the network — without any central authority.

-----

## Key Differentiators

|Feature                  |Standard Kademlia|AuthKademlia-RS                     |
|-------------------------|-----------------|------------------------------------|
|Record integrity         |None             |Cryptographic signature verification|
|Identity support         |None             |Native DID Document storage         |
|Post-quantum cryptography|None             |Dilithium & Kyber key support       |
|Verifiable Data Registry |None             |Built-in VDR semantics              |
|Language                 |Various          |Rust (memory-safe, high-performance)|

-----

## Signed Records and Verifiable Data Registry

Each value stored in the DHT is a **structured signed record** with the following layout:

```
algorithm (12 bytes) | signature | DID Document (canonical JSON)
```

This structure allows any peer to:

- Verify the **authenticity** of stored data using the public key embedded in the DID Document
- Verify the **integrity** of the record against its signature
- Operate without trusting any single node or coordinator

Signature validation is handled automatically by the integrated verifier at insertion and retrieval time.

-----

## Network Layer & Application-Level Fragmentation

Since Post-Quantum Cryptography (PQC) records—containing Dilithium signatures and Kyber keys—often exceed the standard UDP MTU, **AuthKademlia-RS** implements a custom application-level fragmentation and reassembly system.

This ensures that messages remain within safe network limits, avoiding unreliable IP-level fragmentation and improving delivery rates across different network topologies.

### The Message Pipeline

When a node publishes or retrieves a record, the data passes through a structured lifecycle:

1.  **Serialize**: The record is serialized using `bincode` for high-performance binary encoding.
2.  **Split**: The payload is split into chunks of up to **1400 bytes** each, every chunk prefixed with a `KADF` header. A typical Dilithium-2 record (~6 KB) produces 5 fragments.
3.  **Send**: Fragments are transmitted independently from sender to receiver.
4.  **Recv**: The receiver populates a `ReassemblyMap` keyed by `(peer_addr, frag_id)`; slots fill as fragments arrive.
5.  **Assemble**: Once all fragments are received, they are concatenated in index order.
6.  **Dispatch**: The reassembled payload is deserialized and dispatched (e.g. `rpc_store()`), followed by cryptographic signature verification.
7.  **Response**: A result message is sent back to the sender to acknowledge the operation.

### Wire Format

Each UDP datagram sent by this layer has the following layout (all multi-byte integers big-endian):

```
[magic: 4 B "KADF"][frag_id: 4 B u32][index: 2 B u16][total: 2 B u16][payload: variable]
```

Total header: **12 bytes**. `frag_id` is unique per logical message per sender. `index` is 0-based; `total` is the number of fragments (≥ 1). When `total == 1` the datagram carries the entire frame.

By inspecting fragments you can identify the internal composition of a PQC record:
* **Dilithium-2 signature** (2420 B): spans roughly the first two fragments.
* **DID Document JSON** (with base64-encoded Kyber/Dilithium public keys): in the remaining fragments.

-----

## Performance & Concurrency

| Mechanism | Detail |
|---|---|
| **Concurrent storage** | `DashMap` replaces `IndexMap + RwLock`. Storage operations on different keys are fully parallel with no single global lock. |
| **Lazy TTL expiry** | Expired entries are filtered at read time instead of an O(n) scan on every write. |
| **Signature cache** | `SignatureCache` (moka, SHA-256 keyed, TTL 1 h, 4096 entries). Repeated reads of the same record pay full Dilithium cost only once; subsequent reads are O(1). Any byte-level change forces full re-verification. |
| **Worker pool** | UDP datagrams are dispatched via a bounded `mpsc::channel(1024)` into 4 fixed workers, capping task count under burst load and providing backpressure. |
| **Fire-and-forget routing** | Routing table updates (`welcome_if_new`) are spawned as background tasks in all RPC handlers. RPC responses are sent immediately without waiting for routing convergence. |
| **Replication filter** | On node join, only nodes XOR-closer to a key than the new node replicate it (Kademlia §2.5). Prevents redundant store RPCs from far-away nodes. |
| **Atomic insert** | `rpc_store` uses a DashMap `Entry`-based `insert_if_absent` — eliminates the TOCTOU race window that existed with the old read-then-write pattern. |

### Stress test limits

Measured on a single machine (3 local nodes, loopback, `examples/stress_test.rs`).
Each operation is a full `set` → `get` round-trip including Dilithium-2 signature
verification (~5 ms CPU per record).

| Concurrency | Ops | Result |
|---|---|---|
| 10 | 1 000 | Stable — all ops succeed, p99 well under 5 s RPC timeout |
| 20 | 1 000 | Stable |
| 30 | 1 000 | Stable |
| 50 | 1 000 | Stable — practical maximum for real-time use |
| 60 | 1 000 | Degraded — Dilithium-2 CPU backlog starts to overflow the 5 s RPC timeout; occasional failures |
| 80 | 1 000 | Unstable — node saturation; significant failure rate |

**Bottleneck**: Dilithium-2 signature verification (~5 ms/record × 4 workers = ~800
ops/s peak throughput). At concurrency ≥ 60, the verification queue grows faster
than workers drain it and RPC calls begin to time out.

**Mitigations already in place**: the shared `SignatureCache` means each unique
record is verified at most once per hour. In production workloads with repeated
reads the effective throughput is much higher than the raw numbers above.

### Signature cache benchmark

Measured with `examples/cache_bench.rs` — two isolated 3-node loopback clusters
(one with `use_cache = true`, one with `use_cache = false`) running the same
workload: SET a fresh DID Document, cold GET (first application-layer read),
warm GET (second read of the same key).

**Representative run — 300 ops, concurrency 20** (`cargo run --release --example cache_bench -- 300 20`):

| Operation | Cached (avg) | Uncached (avg) | Speedup |
|---|---|---|---|
| SET | 6.6 ms | 7.7 ms | 1.2× |
| GET cold | 38 µs | 98 µs | **2.6×** |
| GET warm | 13 µs | 104 µs | **8.2×** |

All runs (100–400 ops, concurrency 10–30): 0 failures, 0 data corruptions.

**How to read the numbers:**

- *SET*: marginally faster with cache because `rpc_store` handlers on the
  receiving nodes benefit from cross-layer pre-warming (shared `Arc<SignatureCache>`
  between `Server` and `KademliaProtocol`).
- *GET cold*: the "cold" application-layer read is already a cache hit in the
  cached case — when `call_store_rpc` delivers the record to a node, `rpc_store`
  verifies and caches it in the same shared `SignatureCache` that `Server::get`
  later queries. So the first `get()` call sees a cache hit instead of a
  Dilithium-2 re-verification.
- *GET warm*: the primary signal — SHA-256 cache lookup (~12 µs) vs full
  Dilithium-2 re-verification (~100 µs) = **5–8× speedup** depending on load.

The cache can be disabled per-node (`Server::new(..., use_cache: false)`) for
security auditing or benchmarking without touching any other code path.

-----

## DID:IIoT Integration

This implementation is designed to interoperate with the [`did:iiot` method](https://github.com/fratrung/did-iiot), an open DID method targeting **Industrial IoT** environments.

DID Documents stored in the DHT embed **post-quantum public keys** (Dilithium for authentication, Kyber for key exchange), enabling:

- Secure device authentication
- Post-quantum key exchange
- Verifiable credential issuance and resolution

A complete end-to-end integration example is available at [fratrung/did-iiot-dht](https://github.com/fratrung/did-iiot-dht).

-----

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
authkademlia-rs = { git = "https://github.com/fratrung/auth_kademlia" }
```

-----

## Example

```rust
use std::sync::Arc;
use std::path::PathBuf;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use pqcrypto_traits::kem::PublicKey as KemPublicKey;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

/// Encode a raw public key as base64url (no padding).
fn base64url_encode(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

/// Serialize a DID Document to canonical JSON bytes (sorted keys, no spaces).
fn encode_did_document(doc: &Value) -> Vec<u8> {
    // serde_json does not guarantee key order on serialization of arbitrary
    // Value objects, so we convert to a BTreeMap-backed Value first.
    let canonical = sort_json_keys(doc);
    serde_json::to_vec(&canonical).expect("DID Document serialization failed")
}

/// Recursively sort all object keys so serialization is deterministic.
fn sort_json_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let sorted: serde_json::Map<String, Value> = map
                .iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect();
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

/// Build the signed record:
///
/// ```text
/// | algorithm (12 bytes, null-padded) | Dilithium signature | DID Document (JSON) |
/// ```
fn build_signed_record(
    doc: &Value,
    secret_key: &dilithium2::SecretKey,
    algorithm: &str,
) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);

    // Pack algorithm into exactly 12 bytes (UTF-8, null-padded on the right).
    let mut alg_field = [0u8; 12];
    let alg_bytes = algorithm.as_bytes();
    let copy_len = alg_bytes.len().min(12);
    alg_field[..copy_len].copy_from_slice(&alg_bytes[..copy_len]);

    // Sign using the detached API — returns only the signature bytes.
    let detached_sig = dilithium2::detached_sign(&doc_bytes, secret_key);
    let signature = detached_sig.as_bytes();

    // Concatenate: alg_field || signature || doc_bytes
    let mut record = Vec::with_capacity(12 + signature.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(signature);
    record.extend_from_slice(&doc_bytes);
    record
}

/// Generate a `did:iiot` URI using a random UUID v4.
fn generate_did_iiot() -> String {
    format!("did:iiot:{}", Uuid::new_v4())
}

/// Build a minimal `did:iiot` DID Document with one Dilithium and one Kyber key.
fn build_did_document(
    did: &str,
    dilithium_pk: &dilithium2::PublicKey,
    kyber_pk: &kyber512::PublicKey,
) -> Value {
    let dilithium_x = base64url_encode(dilithium_pk.as_bytes());
    let kyber_x = base64url_encode(kyber_pk.as_bytes());

    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Dilithium2",
                    "x": dilithium_x
                }
            },
            {
                "id": format!("{}#k1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Kyber512",
                    "x": kyber_x
                }
            }
        ],
        "authentication": [ format!("{}#k0", did) ],
        "keyAgreement":   [ format!("{}#k1", did) ],
        "service": [
            {
                "id": format!("{}#device", did),
                "type": "DeviceAgent",
                "serviceEndpoint": "http://example.com/device"
            }
        ]
    })
}

async fn start_node(port: u16) -> Server {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from("issuer.bin")));
    let mut server = Server::new(handler, 20, 3, None, None);
    server.listen(port, "127.0.0.1").await.expect("failed to bind UDP socket");
    server
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let node_1 = start_node(5678).await;
    let node_2 = start_node(5679).await;

    // Bootstrap node_2 into the network via node_1.
    let discovered = node_2.bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;
    if discovered.is_empty() {
        eprintln!("Bootstrap returned no peers — is node_1 reachable?");
        return Ok(());
    }

    // Generate PQC keypairs and build a DID Document.
    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let (kyber_pk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let did_doc = build_did_document(&did, &dilithium_pk, &kyber_pk);
    let dht_key = did.split(':').next_back().expect("invalid DID format").to_string();
    let signed_record = build_signed_record(&did_doc, &dilithium_sk, "Dilithium-2");

    // Publish: set() returns None if the key exists or the signature is invalid.
    match node_2.set(&dht_key, signed_record).await {
        Some(true) => println!("Record published under key {}", dht_key),
        _ => {
            eprintln!("Failed to publish record");
            return Ok(());
        }
    }

    // Retrieve from a different node.
    match node_1.get(&dht_key).await {
        Some(record) => {
            let doc_start = 12 + dilithium2::signature_bytes();
            if let Ok(doc) = serde_json::from_slice::<Value>(&record[doc_start..]) {
                println!("Retrieved DID: {}", doc["id"]);
            }
        }
        None => eprintln!("Record not found"),
    }

    Ok(())
}

```

## Logging

AuthKademlia-RS uses the [`log`](https://docs.rs/log) crate with [`env_logger`](https://docs.rs/env_logger) as the backend. To enable debug output in your application:

```rust
env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
```

When running tests or the binary directly, use the `RUST_LOG` environment variable:

```bash
RUST_LOG=debug cargo test -- --nocapture
RUST_LOG=auth_kademlia_rs=trace cargo run --bin dht_node
```

-----

## Python Bindings (experimental)

An optional Python extension can be built with [maturin](https://github.com/PyO3/maturin):

```bash
maturin develop --features python
```

> **Note:** The `python` feature builds a `cdylib` target via PyO3. Do **not** enable it in Rust-only deployments — the `cdylib` crate type changes linking behaviour and is unnecessary outside of Python extension builds. The Python bindings are experimental and not covered by the same stability guarantees as the Rust API.

-----

## Related Projects

- [AuthKademlia](https://github.com/fratrung/AuthKademlia) — original Python implementation
- [did:iiot](https://github.com/fratrung/did-iiot) — DID method for Industrial IoT
- [did-iiot-dht](https://github.com/fratrung/did-iiot-dht) — end-to-end integration example