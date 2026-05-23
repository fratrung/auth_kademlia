# CLAUDE.md — auth-kademlia-rs

## What this is
Kademlia DHT in Rust with **authenticated records**: every stored value is a
self-signed DID Document (post-quantum: Dilithium-2 signature + Kyber-512 key
agreement). Nodes accept a record only if the embedded signature is valid;
updates and deletes require a second auth-signature produced with the owner's
private key.

**Target platform**: edge/embedded nodes (ARM multi-core, low per-core frequency)
for the `did:iiot` method. The Rust core is the performance-critical layer:
Dilithium-2 verification is CPU-bound (~5 ms on x86) and Python's GIL would
serialise it to a single core. The PyO3 binding releases the GIL before
entering Rust so all available cores can verify signatures in parallel.
Application-layer logic (provisioning, REST APIs, orchestration) remains in Python.

## Build & test
```
cargo build                          # library + dht_node binary
cargo build --bin dht_node           # only the Docker entry point
cargo test                           # all 131 tests
cargo test <name>                    # single test, e.g. test_delete_did_record
RUST_LOG=debug cargo test -- --nocapture   # verbose output
```

Python extension (maturin, optional — do not use in Rust-only deployments):
```
maturin develop --features python
```

## Module map
| File | Role |
|---|---|
| `src/protocol.rs` | UDP transport, fragmentation, RPC dispatch (`rpc_store`, `rpc_update`, `rpc_delete`, `rpc_find_node`, `rpc_find_value`) |
| `src/network.rs` | Public `Server` API: `set/get/update/delete`, bootstrap, refresh loop |
| `src/crawling.rs` | Iterative lookup — `NodeSpiderCrawl` (find nodes) + `ValueSpiderCrawl` (find value) |
| `src/routing.rs` | Kademlia routing table + k-buckets (XOR distance, bucket splits) |
| `src/storage.rs` | `ForgetfulStorage` — sharded concurrent TTL KV store (`DashMap`); lazy expiry on read |
| `src/signature_cache.rs` | `SignatureCache` — moka bounded cache (SHA-256 key, TTL 1 h, 4096 entries) for Dilithium verification results |
| `src/fragmentation.rs` | KADF fragmentation + reassembly (`encode_fragments`, `parse_fragment`, `ReassemblyMap`) |
| `src/auth_handler.rs` | `SignatureVerifierHandler` trait + `DIDSignatureVerifierHandler` (DID record verification) |
| `src/crypto/signature_verifier.rs` | `SignatureVerifier` trait, `resolve_alg_and_length()`, algorithm registry |
| `src/crypto/factory.rs` | `SignatureVerifierFactory` + `SignerFactory` — dispatch by algorithm string |
| `src/crypto/dilithium.rs` | Dilithium-2/3/5 verifier + signer |
| `src/crypto/ed25519.rs` | Ed25519 verifier + signer |
| `src/crypto/rsa.rs` | RSA verifier + signer |
| `src/crypto/key_manager.rs` | `KeyManager` — keypair generation, storage, sign/verify helpers |
| `src/node.rs` | `Node` struct, XOR distance, `from_id`; `Display` shows `ip:port` for real peers, `<key:hex8>` for key-space targets |
| `src/utils.rs` | `digest()` (SHA-1 → `[u8; 20]`), `digest_bytes()`, `ID_LEN = 20` |
| `scripts/dht_node.rs` | Docker container entry point (`publisher` / `retriever` roles) |
| `tests/common/mod.rs` | Shared test helpers: `start_node`, `build_did_document`, `build_signed_record`, `generate_did_iiot` |

## Wire record format
```
| algorithm  (12 B, null-padded UTF-8) |
| signature  (2420 B for Dilithium-2)  |
| DID Document (JSON, canonical/sorted keys) |
```
The algorithm field drives `resolve_alg_and_length()` in
`src/crypto/signature_verifier.rs` to pick the right verifier and signature
length. Supported: `Dilithium-2/3/5` (2420/3293/4595 B), `Ed25519` (64 B), `RSA` (256 B).

## Application-level fragmentation (`src/fragmentation.rs`)
Large PQ records (~6 KB) are split into 1400-byte chunks before sending.
Wire format per UDP datagram (all integers big-endian):
```
[magic: 4 B "KADF"][frag_id: u32 4 B][index: u16 2 B][total: u16 2 B][payload]
```
Total header: **12 bytes**. `frag_id` is unique per logical message per sender.
`index` is 0-based; `total` is the number of fragments (≥ 1).
Constants: `FRAG_CHUNK_SIZE=1400`, `FRAG_HEADER_LEN=12`,
`MAX_MESSAGE_SIZE=256 KB`, `REASSEMBLY_TTL=10 s`.
`handle_datagram()` in `protocol.rs` reassembles transparently before deserialising.
Oversized messages (projected size > `MAX_MESSAGE_SIZE`) are discarded before
entering the reassembly buffer to bound memory usage.

## RPC message types (`src/protocol.rs`)
| Variant | Direction | Purpose |
|---|---|---|
| `Ping` / `Pong` | req/resp | Liveness check + node discovery |
| `Store` / `StoreResult` | req/resp | Store a new authenticated record |
| `Update` / `UpdateResult` | req/resp | Key-rotation update (requires `auth_signature`) |
| `UpdateStatusList` / `UpdateStatusListResult` | req/resp | Issuer-signed status-list update |
| `Delete` / `DeleteResult` | req/resp | Authenticated record deletion |
| `FindNode` / `FindNodeResult` | req/resp | Kademlia FIND_NODE |
| `FindValue` / `FindValueHit` / `FindValueNodes` | req/resp | Kademlia FIND_VALUE |
| `Leave` | fire-and-forget | Graceful departure, removes node from routing table |

All RPCs are serialised with `bincode` and framed with a `(msg_id: u32, is_request: bool, message)` envelope. Responses are correlated via `msg_id` through a `PendingMap`.

## Concurrency model
- `ForgetfulStorage` is `Arc<ForgetfulStorage>` (no outer `RwLock`). All `IStorage` methods take `&self`; internal synchronization via `DashMap` shards.
- `rpc_store` uses `insert_if_absent` (DashMap `Entry` API) — atomic at shard level, closes the TOCTOU race between "does key exist?" and "write it".
- All RPC handlers use `self: &Arc<Self>` receiver to enable `tokio::spawn` without cloning the full struct. `welcome_if_new` is always fire-and-forget.
- UDP receive loop spawns one Tokio task per datagram. An `inflight` semaphore (capacity 1024) in `network.rs::listen()` bounds the number of tasks in flight: when full, the datagram is dropped (UDP-native backpressure — bounds memory under load). Responses take the fast path (no semaphore). Requests invoke `req_sem` (sized to `available_parallelism()`) only around the `spawn_blocking` crypto call, so fast RPCs (ping, find_node) are never gated.
- `SignatureCache` is keyed on `SHA-256(record_bytes)`. TTL 1 h, capacity 4096 (moka TinyLFU). Eviction = cache miss = full re-verification (never a security bypass). On a cache miss the SHA-256 key is computed once via `compute_key()` and reused for both `get_by_key` and `insert_by_key` — never twice.
- `welcome_if_new` replication uses two conditions (Kademlia §2.5, matches Python AuthKademlia): `new_node_close` (new node is XOR-closer than the farthest k-neighbor) AND `this_closest` (this node is closer than the nearest k-neighbor). Both must be true to replicate. Neighbors are computed before `add_contact` so the new node is excluded from comparisons.

## Key invariants
- Records are **immutable after creation**: `rpc_store` rejects duplicate keys.
- `set()` performs a single `ValueSpiderCrawl` (FIND_VALUE): if a valid record is found the store is rejected; if not, the k-closest nodes returned by the crawl are reused directly for STORE, avoiding a second network traversal (Kademlia §2.3).
- Updates require `auth_signature = sign(new_record_bytes, old_private_key)`.
  `verify_key_rotation()` checks: (1) auth_sig valid under old public key, (2) new record self-signed.
  **Downgrade attacks are impossible**: to submit `record_v1` as "new" when `record_v2`
  is stored, an attacker would need to sign with `sk_v2` — which they do not possess.
- Deletes require `auth_signature = sign(delete_msg, owner_private_key)`.
- DHT key = `digest(did_uuid_string)` where `digest` is SHA-1 → `[u8; 20]`.
- `STATUS_LIST_KEY = digest("did:iiot:status-list")` uses issuer-node
  verification instead of DID-owner verification.
- `issuer.bin` is read lazily; if absent, a `log::warn!` is emitted at startup
  and only `STATUS_LIST_KEY` operations are affected (normal DID records are not).

## Test suite structure
| File | Count | Notes |
|---|---|---|
| `tests/network_tests.rs` | 8 | Full multi-node integration tests (real UDP) |
| `tests/crypto_tests.rs` | 27 | Crypto layer unit + DID handler unit tests |
| `tests/routing_tests.rs` | 20 | Routing table unit tests |
| `tests/storage_tests.rs` | 17 | `ForgetfulStorage` unit tests (includes `insert_if_absent` cases) |
| `tests/dht_integration.rs` | 1 | Legacy 3-node end-to-end scenario |
| `src/**` (inline) | 56 | Module-level `#[test]` blocks |

All tests are network-clean (loopback only) and run in parallel without interference when port ranges are respected.

## Test port allocation (run in parallel — do not reuse)
| Range | Test |
|---|---|
| 15700–15701 | two-node bootstrap |
| 15710–15711 | cross-node set/get |
| 15720–15721 | duplicate key rejection |
| 15730–15732 | key-rotation update |
| 15740–15741 | authenticated delete |
| 15750 | invalid signature rejection |
| 15760 | unreachable peer |
| 15780–15781 | update rejected on invalid new-record self-signature |
| 15782–15784 | update rejected when auth_sig uses wrong key |
| 15785–15786 | delete rejected when signature uses wrong key |

When adding a new integration test use ports **15787+** and document them here.

## Docker
```
docker compose up --build            # 4 containers: seed, peer1, peer2, peer3
docker compose logs -f dht_peer_2   # follow a single container
```
`DEMO_DID_UUID` in `.env` is the shared key for the publisher→retriever demo.
Environment variables per container: `NODE_PORT`, `IS_SEED`, `BOOTSTRAP_ADDR`,
`ROLE` (`publisher`|`retriever`), `FIXED_DID_UUID`, `RETRIEVE_KEY`, `RUST_LOG`.

## Adding a new crypto algorithm
1. Implement `SignatureVerifier` (and optionally `Signer`) in `src/crypto/<alg>.rs`.
2. Register in `src/crypto/factory.rs` → `SignatureVerifierFactory::create()` and `SignerFactory::create()`.
3. Add the algorithm string + signature length to `resolve_alg_and_length()` in
   `src/crypto/signature_verifier.rs`.
4. Add tests in `tests/crypto_tests.rs`.

## Session continuity — RESUME_BEFORE_COMPACT.md

When the conversation is approaching context limits and a `/compact` is imminent,
write a file `RESUME_BEFORE_COMPACT.md` in the project root **before** the compact
happens. This file lets the next context window pick up exactly where the session
left off.

The file must contain:
1. **Current task** — what the user is working on right now, in one sentence.
2. **Pending actions** — any commits not yet created, PRs not yet opened, commands
   not yet run, open questions awaiting an answer.
3. **Key decisions made this session** — non-obvious choices and why they were made
   (architecture, algorithm, workaround). Skip anything obvious from the code.
4. **Files changed** — list of modified files with one-line summaries of what changed.
5. **Known issues / blockers** — anything broken, half-finished, or needing follow-up.

Keep it concise (≤ 60 lines). The file is ephemeral: delete it once the first
message of the new session confirms the context has been picked up.

## What NOT to do
- Do not hold a `Mutex` lock across an `.await` — deadlock risk.
- Do not increase `MAX_MESSAGE_SIZE` without a matching memory-budget review.
- Do not add `unwrap()` in protocol/network paths — use `?` or log + return.
- Do not add new integration tests on already-used port ranges.
- Do not enable the `python` feature in Rust-only deployments (`cdylib` changes linking).
- Do not add an `"updated"` timestamp field to DID Documents for ordering: downgrade
  attacks are already prevented by the auth-signature chain; the field would be
  redundant and would break compatibility with existing records without a migration.
