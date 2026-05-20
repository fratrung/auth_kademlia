# Changelog

All notable changes to this project are documented here.

---

## [Unreleased] — 2026-05-20

### Performance

- **Concurrent storage (DashMap)** — replaced `IndexMap + RwLock` with `DashMap`.
  Storage operations on different keys are now fully parallel with no single
  global lock. The outer `Arc<RwLock<ForgetfulStorage>>` has been removed;
  `ForgetfulStorage` is now `Arc<ForgetfulStorage>` directly.

- **Lazy TTL expiry** — expired entries are now filtered on read instead of
  being eagerly culled on every write. Eliminates the O(n) `cull()` pass that
  ran on every `set()` and `delete()`.

- **Signature cache** — `SignatureCache` (moka, SHA-256 keyed, TTL 1 h, 4096
  entries) added to both `KademliaProtocol` and `Server`. Repeated calls to
  `verify_for_key` / `verify_value` with the same record bytes pay full
  Dilithium cost only on the first call; subsequent calls are O(1). Any
  byte-level change to a record produces a cache miss and forces full
  re-verification.

- **Worker pool for UDP datagrams** — the receive loop now dispatches datagrams
  through a bounded `mpsc::channel(1024)` into a fixed pool of 4 workers,
  replacing unbounded per-datagram `tokio::spawn`. This caps task count under
  burst load and provides natural backpressure.

- **Fire-and-forget `welcome_if_new`** — routing table updates in all RPC
  handlers (`rpc_ping`, `rpc_store`, `rpc_update`, `rpc_update_status_list`,
  `rpc_delete`, `rpc_find_node`, `rpc_find_value`) are now spawned as
  background tasks. RPC responses are sent immediately without waiting for
  routing table convergence.

- **Replication filter in `welcome_if_new`** — when a new node joins, only
  nodes that are XOR-closer to a key than the new node replicate it. Prevents
  redundant store RPCs from far-away nodes (Kademlia §2.5 responsible-node
  invariant).

### Security

- **Atomic `insert_if_absent`** — `rpc_store` now uses a single DashMap
  `Entry`-based operation instead of a read-then-write sequence, closing the
  TOCTOU race window that could allow duplicate records under concurrent
  requests. Signature verification still runs before the insert.

- **Local read verification restored** — `Server::get()` re-verifies the
  Dilithium signature on local storage hits via the signature cache. This
  matches the paper specification (§4.4): the requesting node verifies the
  signature before accepting a record, regardless of whether it came from the
  network or local storage. The cache ensures this adds no measurable overhead
  on repeated reads of the same record.

### Code quality

- Removed all `P1`–`P7` task-reference labels from inline comments; replaced
  with intent-describing text.
- Removed stale `RwLock` references from doc comments and field comments.
- Updated `IStorage` trait: all methods now take `&self` (no `&mut self`);
  internal synchronization is the implementation's responsibility.
- Added `insert_if_absent` to `IStorage` trait and `ForgetfulStorage`.
- `tests/storage_tests.rs`: removed all `let mut s` bindings (now unnecessary).
- Clippy fixes across all targets: `div_ceil`, `is_none_or`, `next_back()`,
  doc indentation.

### Dependencies

- Added `dashmap = "6"` — sharded concurrent hashmap.
- Added `moka = { version = "0.12", features = ["sync"] }` — bounded cache
  with TTL and size-based eviction.

---

## [0.1.0] — initial release

- Kademlia DHT with authenticated DID Document records (Dilithium-2 / Kyber-512).
- Wire format: `[algorithm 12 B | signature 2420 B | DID Document JSON]`.
- KADF fragmentation for large PQ records over UDP (1400-byte chunks).
- `rpc_store`, `rpc_update`, `rpc_delete`, `rpc_find_node`, `rpc_find_value`.
- `did:iiot` DID method support; Status-List via Issuer Node.
- Python bindings via pyo3 0.21 + pyo3-async-runtimes (optional feature).
- Docker Compose testbed with seed + 3 peer containers.
