# CLAUDE.md — auth-kademlia-rs

## What this is
Kademlia DHT in Rust with **authenticated records**: every stored value is a
self-signed DID Document (post-quantum: Dilithium-2 signature + Kyber-512 key
agreement). Nodes accept a record only if the embedded signature is valid;
updates and deletes require a second auth-signature produced with the owner's
private key.

## Build & test
```
cargo build                          # library + dht_node binary
cargo build --bin dht_node           # only the Docker entry point
cargo test                           # all 53 tests (no network required)
cargo test <name>                    # single test, e.g. test_delete_did_record
RUST_LOG=debug cargo test -- --nocapture   # verbose output
```

Python extension (maturin, optional):
```
maturin develop --features python
```

## Module map
| File | Role |
|---|---|
| `src/protocol.rs` | UDP transport, fragmentation, RPC dispatch |
| `src/network.rs` | Public `Server` API: `set/get/update/delete` |
| `src/crawling.rs` | Iterative lookup (NodeSpider / ValueSpider) |
| `src/routing.rs` | Kademlia routing table + k-buckets |
| `src/storage.rs` | `ForgetfulStorage` — TTL-based KV store |
| `src/auth_handler.rs` | `SignatureVerifierHandler` trait + DID implementation |
| `src/crypto/` | Dilithium, Kyber, Ed25519, RSA verifiers + `KeyManager` |
| `src/node.rs` | `Node` struct, XOR distance |
| `src/utils.rs` | `digest()` (SHA-1 → `[u8; 20]`), `ID_LEN = 20` |
| `scripts/dht_node.rs` | Docker container entry point |

## Wire record format
```
| algorithm  (12 B, null-padded UTF-8) |
| signature  (2420 B for Dilithium-2)  |
| DID Document (JSON, canonical/sorted keys) |
```
The algorithm field drives `resolve_alg_and_length()` in
`src/crypto/signature_verifier.rs` to pick the right verifier and signature
length. Supported: `Dilithium-2/3/5`, `Ed25519`, `RSA`.

## Application-level fragmentation (`protocol.rs`)
Large PQ records (~6 KB) are split into 1400-byte chunks before sending.
Wire format per UDP datagram:
```
[magic: 4 B "KADF"][frag_id: u32 BE][index: u16 BE][total: u16 BE][payload]
```
Constants: `FRAG_CHUNK_SIZE=1400`, `FRAG_HEADER_LEN=12`,
`MAX_MESSAGE_SIZE=256 KB`, `REASSEMBLY_TTL=10 s`.
`handle_datagram()` reassembles transparently before deserialising.

## Key invariants
- Records are **immutable after creation**: `rpc_store` rejects duplicate keys.
- `set()` calls `get()` first — returns `None` if the key already exists.
- Updates require `auth_signature = sign(new_record, old_private_key)`.
- Deletes require `auth_signature = sign(delete_msg, owner_private_key)`.
- DHT key = `digest(did_uuid_string)` where `digest` is SHA-1 → `[u8; 20]`.
- `STATUS_LIST_KEY = digest("did:iiot:status-list")` uses issuer-node
  verification instead of DID-owner verification.

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

When adding a new integration test use ports **15770+** and document them here.

## Docker
```
docker compose up --build            # 4 containers: seed, peer1, peer2, peer3
docker compose logs -f dht_peer_2   # follow a single container
```
`DEMO_DID_UUID` in `.env` is the shared key for the publisher→retriever demo.
Environment variables per container: `NODE_PORT`, `IS_SEED`, `BOOTSTRAP_ADDR`,
`ROLE` (`publisher`|`retriever`), `FIXED_DID_UUID`, `RETRIEVE_KEY`, `RUST_LOG`.

## Adding a new crypto algorithm
1. Implement `SignatureVerifier` in `src/crypto/<alg>.rs`.
2. Register in `src/crypto/factory.rs` → `SignatureVerifierFactory::create()`.
3. Add the algorithm string + signature length to `resolve_alg_and_length()` in
   `src/crypto/signature_verifier.rs`.
4. Add tests in `tests/crypto_tests.rs`.

## What NOT to do
- Do not hold a `Mutex` lock across an `.await` — deadlock risk.
- Do not increase `MAX_MESSAGE_SIZE` without a matching memory-budget review.
- Do not add `unwrap()` in protocol/network paths — use `?` or log + return.
- Do not add new integration tests on already-used port ranges.
