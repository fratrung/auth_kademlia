//! Stress test for AuthKademlia-RS.
//!
//! Launches 3 local nodes, then fires N concurrent SET+GET rounds measuring:
//!   - throughput (ops/sec) and latency distribution (avg, p50, p95, p99, max)
//!   - data integrity (retrieved bytes == stored bytes, byte-exact)
//!   - signature-cache effectiveness (cold vs warm GET latency)
//!
//! After the performance phase, runs 6 targeted security-invariant checks:
//!   1. Valid record accepted
//!   2. Tampered signature rejected
//!   3. Wrong-signer record rejected
//!   4. Unknown algorithm rejected
//!   5. Duplicate key rejected (immutability)
//!   6. TOCTOU: concurrent stores of the same key — record must be consistent
//!
//! Run:
//!   cargo run --release --example stress_test            # 200 ops, 20 concurrent
//!   cargo run --release --example stress_test -- 500     # 500 ops
//!   cargo run --release --example stress_test -- 500 40  # 500 ops, 40 concurrent

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::PublicKey;
use serde_json::{json, Value};
use tokio::task::JoinSet;
use tokio::time::timeout;
use uuid::Uuid;

const SEED_PORT: u16 = 15800;
const PEER1_PORT: u16 = 15801;
const PEER2_PORT: u16 = 15802;

const DEFAULT_OPS: usize = 200;
const DEFAULT_CONCURRENCY: usize = 20;
const OP_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Metrics ─────────────────────────────────────────────────────────────────

/// Metrics collected in the main loop after each task completes.
/// Plain values — no atomics, no mutexes, no Arc: the main task owns this
/// exclusively and updates it sequentially as JoinSet futures resolve.
#[derive(Default)]
struct Phase1Stats {
    set_ok: usize,
    set_fail: usize,
    get_ok: usize,
    get_fail: usize,
    corruptions: usize,
    timeouts: usize,
    set_ns: Vec<u64>,
    get_ns: Vec<u64>,
    cache_ns: Vec<u64>,
}

impl Phase1Stats {
    fn record(&mut self, result: Result<(u64, u64, u64, bool), &'static str>) {
        match result {
            Ok((s, g, c, corrupted)) => {
                self.set_ok += 1;
                self.get_ok += 1;
                if corrupted {
                    self.corruptions += 1;
                }
                self.set_ns.push(s);
                self.get_ns.push(g);
                self.cache_ns.push(c);
            }
            Err(e) if e.contains("timeout") => {
                self.timeouts += 1;
                if e.starts_with("set") {
                    self.set_fail += 1;
                } else {
                    self.get_fail += 1;
                }
            }
            Err(e) if e.starts_with("set") => {
                self.set_fail += 1;
            }
            Err(_) => {
                self.get_fail += 1;
            }
        }
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 * p / 100.0).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn avg_ns(v: &[u64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<u64>() as f64 / v.len() as f64
}

fn fmt_dur(ns: u64) -> String {
    if ns < 1_000 {
        format!("{}ns", ns)
    } else if ns < 1_000_000 {
        format!("{:.1}µs", ns as f64 / 1_000.0)
    } else {
        format!("{:.1}ms", ns as f64 / 1_000_000.0)
    }
}

// ─── DID / Record helpers ────────────────────────────────────────────────────

fn base64url(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

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

fn encode_did_document(doc: &Value) -> Vec<u8> {
    serde_json::to_vec(&sort_json_keys(doc)).expect("serialization failed")
}

fn build_signed_record(doc: &Value, sk: &dilithium2::SecretKey) -> Vec<u8> {
    let doc_bytes = encode_did_document(doc);
    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");
    let sig = dilithium2::detached_sign(&doc_bytes, sk);
    let sig_bytes =
        <dilithium2::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(&sig);
    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    record
}

fn build_did_document(did: &str, dpk: &dilithium2::PublicKey, kpk: &kyber512::PublicKey) -> Value {
    json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2", "x": base64url(dpk.as_bytes()) }
            },
            {
                "id": format!("{}#k1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512", "x": base64url(kpk.as_bytes()) }
            }
        ],
        "authentication": [format!("{}#k0", did)],
        "keyAgreement": [format!("{}#k1", did)],
        "service": [{ "id": format!("{}#device", did), "type": "DeviceAgent",
                      "serviceEndpoint": "http://example.com/device" }]
    })
}

fn new_did() -> (String, String, Vec<u8>, dilithium2::SecretKey) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&did, &dpk, &kpk);
    let record = build_signed_record(&doc, &dsk);
    (did, key, record, dsk)
}

// ─── Node factory ─────────────────────────────────────────────────────────────

async fn start_node(port: u16) -> Arc<Server> {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from(
        "issuer.bin",
    )));
    let mut server = Server::new(handler, 20, 3, None, None, true);
    server
        .listen(port, "127.0.0.1")
        .await
        .expect("listen failed");
    Arc::new(server)
}

// ─── Single stress operation ──────────────────────────────────────────────────

/// One full SET → GET round. Returns (set_ns, get_ns, cache_get_ns, corrupted).
async fn stress_op(
    writer: Arc<Server>,
    reader: Arc<Server>,
) -> Result<(u64, u64, u64, bool), &'static str> {
    let (_did, key, record, _dsk) = new_did();

    let t0 = Instant::now();
    let set_result = timeout(OP_TIMEOUT, writer.set(&key, record.clone()))
        .await
        .map_err(|_| "set timeout")?;
    let set_ns = t0.elapsed().as_nanos() as u64;
    if set_result != Some(true) {
        return Err("set failed");
    }

    // First GET: cold path (signature verification + possible DHT crawl)
    let t1 = Instant::now();
    let retrieved = timeout(OP_TIMEOUT, reader.get(&key))
        .await
        .map_err(|_| "get timeout")?
        .ok_or("get returned None")?;
    let get_ns = t1.elapsed().as_nanos() as u64;

    // Byte-exact integrity check: detects storage-level corruption (DashMap races)
    // or protocol-level data mangling. Note: get() already verifies the Dilithium
    // signature internally — if it returns Some, the signature is valid. This check
    // catches a different class of bugs: correct signature on wrong/corrupted bytes.
    let corrupted = retrieved != record;

    // Second GET on same reader: should hit the local storage + signature cache
    let t2 = Instant::now();
    let _ = timeout(OP_TIMEOUT, reader.get(&key))
        .await
        .map_err(|_| "get2 timeout")?;
    let cache_ns = t2.elapsed().as_nanos() as u64;

    Ok((set_ns, get_ns, cache_ns, corrupted))
}

// ─── Security phase ───────────────────────────────────────────────────────────

struct Check {
    name: &'static str,
    passed: bool,
    detail: String,
}

impl Check {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            passed: true,
            detail: detail.into(),
        }
    }
    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            passed: false,
            detail: detail.into(),
        }
    }
}

async fn run_security_checks(nodes: &[Arc<Server>]) -> Vec<Check> {
    let mut results = Vec::new();
    let writer = &nodes[0];
    let reader = &nodes[1];

    // ── Check 1: Valid record is accepted ─────────────────────────────────────
    {
        let (_did, key, record, _) = new_did();
        let r = timeout(OP_TIMEOUT, writer.set(&key, record)).await;
        let ok = matches!(r, Ok(Some(true)));
        results.push(if ok {
            Check::pass("Valid record accepted", "set() returned Some(true)")
        } else {
            let diagnosis = match &r {
                Err(_) => "timeout — node unreachable or overloaded",
                Ok(None) => "None — signature invalid or key already exists (unexpected)",
                Ok(Some(false)) => "Some(false) — spider crawl returned 0 reachable nodes (routing degraded); run with RUST_LOG=warn for details",
                _ => "unexpected variant",
            };
            Check::fail("Valid record accepted", format!("set() returned {r:?} [{diagnosis}]"))
        });
    }

    // ── Check 2: Tampered signature rejected ──────────────────────────────────
    // Flip a byte deep inside the Dilithium signature (bytes 12..2432).
    // The node must reject this at verify_for_key() before storing.
    {
        let (_did, key, mut record, _) = new_did();
        record[500] ^= 0xFF; // corrupt signature byte
        let r = timeout(OP_TIMEOUT, writer.set(&key, record)).await;
        // Server::set() calls verify_value() before set_digest → returns None on failure
        let ok = matches!(r, Ok(None));
        results.push(if ok {
            Check::pass(
                "Tampered signature rejected",
                "set() returned None (signature mismatch)",
            )
        } else {
            Check::fail(
                "Tampered signature rejected",
                format!("expected None, got {r:?}  ← SECURITY FAILURE"),
            )
        });
    }

    // ── Check 3: Wrong-signer record rejected ─────────────────────────────────
    // DID Document embeds pubkey_A, but the record is signed with privkey_B.
    // The verifier extracts pubkey_A from the doc and uses it to verify the
    // signature made by privkey_B → mismatch → rejected.
    {
        let (dpk_a, _dsk_a) = dilithium2::keypair(); // key that goes into the doc
        let (_dpk_b, dsk_b) = dilithium2::keypair(); // key actually used for signing
        let (kpk, _) = kyber512::keypair();
        let did = format!("did:iiot:{}", Uuid::new_v4());
        let key = did.split(':').next_back().unwrap().to_string();
        let doc = build_did_document(&did, &dpk_a, &kpk); // pubkey_A in doc
        let record = build_signed_record(&doc, &dsk_b); // signed with privkey_B
        let r = timeout(OP_TIMEOUT, writer.set(&key, record)).await;
        let ok = matches!(r, Ok(None));
        results.push(if ok {
            Check::pass(
                "Wrong-signer rejected",
                "set() returned None (pubkey/privkey mismatch)",
            )
        } else {
            Check::fail(
                "Wrong-signer rejected",
                format!("expected None, got {r:?}  ← SECURITY FAILURE"),
            )
        });
    }

    // ── Check 4: Unknown algorithm rejected ───────────────────────────────────
    // Override the 12-byte algorithm field with an unknown string.
    // resolve_alg_and_length() will fail → verification aborts → rejected.
    {
        let (_did, key, mut record, _) = new_did();
        record[..12].copy_from_slice(b"UNKNOWN\0\0\0\0\0");
        let r = timeout(OP_TIMEOUT, writer.set(&key, record)).await;
        let ok = matches!(r, Ok(None));
        results.push(if ok {
            Check::pass("Unknown algorithm rejected", "set() returned None")
        } else {
            Check::fail(
                "Unknown algorithm rejected",
                format!("expected None, got {r:?}  ← SECURITY FAILURE"),
            )
        });
    }

    // ── Check 5: Duplicate key rejected (immutability) ────────────────────────
    // Store a valid record, then attempt to store a different valid record
    // under the same DHT key. The second set() must return None because
    // Server::set() calls get() first and finds the existing record.
    {
        let (_did, key, record, _) = new_did();
        let first = timeout(OP_TIMEOUT, writer.set(&key, record.clone())).await;

        if !matches!(first, Ok(Some(true))) {
            let diagnosis = match &first {
                Err(_) => "timeout",
                Ok(None) => "None — signature invalid (bug in test setup)",
                Ok(Some(false)) => {
                    "Some(false) — routing degraded, spider crawl found no reachable nodes"
                }
                _ => "unexpected",
            };
            results.push(Check::fail(
                "Duplicate key rejected",
                format!("first insert failed [{diagnosis}]: {first:?}"),
            ));
        } else {
            // Build a second valid record for the same key (different owner keypair)
            let (dpk2, dsk2) = dilithium2::keypair();
            let (kpk2, _) = kyber512::keypair();
            let did2 = format!("did:iiot:{}", key); // same UUID suffix → same DHT key
            let doc2 = build_did_document(&did2, &dpk2, &kpk2);
            let record2 = build_signed_record(&doc2, &dsk2);

            let second = timeout(OP_TIMEOUT, writer.set(&key, record2)).await;
            let ok = matches!(second, Ok(None));
            results.push(if ok {
                Check::pass(
                    "Duplicate key rejected",
                    "second set() returned None (key already exists)",
                )
            } else {
                Check::fail(
                    "Duplicate key rejected",
                    format!("expected None, got {second:?}  ← IMMUTABILITY VIOLATION"),
                )
            });

            // Also verify the stored record is still the original (not overwritten)
            let stored = timeout(OP_TIMEOUT, reader.get(&key)).await;
            let original_intact = matches!(&stored, Ok(Some(v)) if v == &record);
            results.push(if original_intact {
                Check::pass(
                    "Duplicate key: original preserved",
                    "get() returned original record unchanged",
                )
            } else {
                let diagnosis = match &stored {
                    Err(_) => "timeout — reader node unreachable",
                    Ok(None) => "None — record not found (routing degraded, not overwritten)",
                    Ok(Some(_)) => {
                        "Some(wrong_bytes) — record bytes differ (actual integrity failure)"
                    }
                };
                Check::fail(
                    "Duplicate key: original preserved",
                    format!("stored={stored:?} [{diagnosis}]"),
                )
            });
        }
    }

    // ── Check 6: TOCTOU — concurrent same-key stores ──────────────────────────
    // Fire 15 concurrent set() calls with the same key from different nodes.
    // The insert_if_absent() DashMap Entry ensures at most one copy is stored
    // per node. After all tasks complete, the record must be consistent (same
    // bytes) across all readers — no mix of two different records.
    {
        let (_did, key, record, _) = new_did();
        const N_CONCURRENT: usize = 15;
        let key = Arc::new(key);
        let record = Arc::new(record);
        let success_count = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for i in 0..N_CONCURRENT {
            let node = Arc::clone(&nodes[i % nodes.len()]);
            let k = Arc::clone(&key);
            let r = Arc::clone(&record);
            let sc = Arc::clone(&success_count);
            tasks.push(tokio::spawn(async move {
                if timeout(OP_TIMEOUT, node.set(&*k, (*r).clone())).await == Ok(Some(true)) {
                    sc.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for t in tasks {
            let _ = t.await;
        }

        let successes = success_count.load(Ordering::Relaxed);

        // At least one store must succeed
        let at_least_one = successes >= 1;

        // All nodes that have the record must return the exact same bytes
        let mut consistency_ok = true;
        for node in nodes {
            if let Ok(Some(v)) = timeout(OP_TIMEOUT, node.get(&*key)).await {
                if v != *record {
                    consistency_ok = false;
                }
            }
        }

        let detail = format!(
            "{successes}/{N_CONCURRENT} concurrent stores reported success, \
             all retrieved records consistent: {consistency_ok}"
        );
        let ok = at_least_one && consistency_ok;
        results.push(if ok {
            Check::pass("TOCTOU: concurrent stores consistent", detail)
        } else {
            Check::fail("TOCTOU: concurrent stores consistent", detail)
        });
    }

    results
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let parallelism = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4);
    tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(parallelism)
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime")
        .block_on(run())
}

async fn run() {
    let args: Vec<String> = std::env::args().collect();
    let num_ops: usize = args
        .get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_OPS);
    let concurrency: usize = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CONCURRENCY);

    println!("╔══════════════════════════════════════════════╗");
    println!("║       AuthKademlia-RS  Stress Test           ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  Nodes       : 3  (seed:{SEED_PORT}, peer:{PEER1_PORT}, peer:{PEER2_PORT})");
    println!("  Operations  : {num_ops}");
    println!("  Concurrency : {concurrency}  (semaphore)");
    println!("  Timeout/op  : {}s", OP_TIMEOUT.as_secs());
    println!("  Record size : ~6 KB  (Dilithium-2 + Kyber-512 DID Document)\n");

    print!("Starting nodes... ");
    let seed = start_node(SEED_PORT).await;
    let peer1 = start_node(PEER1_PORT).await;
    let peer2 = start_node(PEER2_PORT).await;
    println!("ok");

    print!("Bootstrapping... ");
    peer1
        .bootstrap(vec![("127.0.0.1".to_string(), SEED_PORT)])
        .await;
    peer2
        .bootstrap(vec![("127.0.0.1".to_string(), SEED_PORT)])
        .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("ok\n");

    let nodes: Vec<Arc<Server>> = vec![seed, peer1, peer2];

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1: Performance
    // ─────────────────────────────────────────────────────────────────────────
    println!("━━━ Phase 1: Performance ━━━━━━━━━━━━━━━━━━━━━━\n");

    // Each task owns its inputs directly — no Arc<Metrics>, no Semaphore, no
    // shared mutable state. The JoinSet drains tasks as they complete, keeping
    // at most `concurrency` futures alive at any point. Memory usage is
    // O(concurrency × task_size) instead of O(num_ops × task_size).
    let mut stats = Phase1Stats {
        set_ns: Vec::with_capacity(num_ops),
        get_ns: Vec::with_capacity(num_ops),
        cache_ns: Vec::with_capacity(num_ops),
        ..Phase1Stats::default()
    };
    let wall = Instant::now();
    let mut completed = 0usize;
    let step = (num_ops / 10).max(1);

    let mut jset: JoinSet<Result<(u64, u64, u64, bool), &'static str>> = JoinSet::new();

    for i in 0..num_ops {
        // Before spawning the next task, drain completed ones until we are
        // strictly below the concurrency limit.
        while jset.len() >= concurrency {
            match jset.join_next().await {
                Some(Ok(result)) => stats.record(result),
                Some(Err(e)) => {
                    // A task panicked — should not happen, but handle it rather
                    // than propagating the panic to the test runner.
                    log::error!("stress op task panicked: {e}");
                    stats.get_fail += 1;
                }
                None => break, // set unexpectedly empty — safety net only
            }
            completed += 1;
            if completed % step == 0 || completed == num_ops {
                print!("\r  Progress: {completed}/{num_ops}");
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
        }

        let writer = Arc::clone(&nodes[i % nodes.len()]);
        let reader = Arc::clone(&nodes[(i + 1) % nodes.len()]);
        jset.spawn(async move { stress_op(writer, reader).await });
    }

    // Drain the tasks that are still in flight after all ops have been spawned.
    while let Some(join_result) = jset.join_next().await {
        match join_result {
            Ok(result) => stats.record(result),
            Err(e) => {
                log::error!("stress op task panicked: {e}");
                stats.get_fail += 1;
            }
        }
        completed += 1;
        if completed % step == 0 || completed == num_ops {
            print!("\r  Progress: {completed}/{num_ops}");
            use std::io::Write;
            let _ = std::io::stdout().flush();
        }
    }

    let elapsed = wall.elapsed();
    println!("\r  Progress: {num_ops}/{num_ops}  ✓\n");

    let set_ok = stats.set_ok;
    let set_fail = stats.set_fail;
    let get_ok = stats.get_ok;
    let get_fail = stats.get_fail;
    let corruptions = stats.corruptions;
    let timeouts = stats.timeouts;

    let mut set_ns = stats.set_ns;
    let mut get_ns = stats.get_ns;
    let mut cache_ns = stats.cache_ns;
    set_ns.sort_unstable();
    get_ns.sort_unstable();
    cache_ns.sort_unstable();

    let throughput = (set_ok + set_fail) as f64 / elapsed.as_secs_f64();
    println!("  Wall time    : {:.2}s", elapsed.as_secs_f64());
    println!("  Throughput   : {throughput:.1} ops/sec");
    println!();
    println!("  SET  ok/fail : {set_ok}/{set_fail}");
    println!("  GET  ok/fail : {get_ok}/{get_fail}");
    println!("  Timeouts     : {timeouts}");
    if corruptions == 0 {
        println!("  Corruptions  : 0  ✓");
    } else {
        println!("  Corruptions  : {corruptions}  ✗  DATA INTEGRITY FAILURE");
    }
    println!();
    println!("  ┌─────────────┬──────────┬──────────┬──────────┬──────────┬──────────┐");
    println!("  │             │   avg    │   p50    │   p95    │   p99    │   max    │");
    println!("  ├─────────────┼──────────┼──────────┼──────────┼──────────┼──────────┤");
    let row = |label: &str, v: &[u64]| {
        if v.is_empty() {
            println!("  │ {label:<11} │   n/a    │   n/a    │   n/a    │   n/a    │   n/a    │");
        } else {
            println!(
                "  │ {:<11} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │",
                label,
                fmt_dur(avg_ns(v) as u64),
                fmt_dur(percentile(v, 50.0)),
                fmt_dur(percentile(v, 95.0)),
                fmt_dur(percentile(v, 99.0)),
                fmt_dur(*v.last().unwrap_or(&0)),
            );
        }
    };
    row("SET", &set_ns);
    row("GET (cold)", &get_ns);
    row("GET (cache)", &cache_ns);
    println!("  └─────────────┴──────────┴──────────┴──────────┴──────────┴──────────┘");
    if !get_ns.is_empty() && !cache_ns.is_empty() {
        let cold = avg_ns(&get_ns);
        let warm = avg_ns(&cache_ns);
        if warm > 0.0 {
            println!(
                "\n  Signature cache speedup : {:.1}×  ({} cold → {} warm)",
                cold / warm,
                fmt_dur(cold as u64),
                fmt_dur(warm as u64)
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2: Security invariants — isolated cluster
    // ─────────────────────────────────────────────────────────────────────────
    // Phase 1 degrades the routing tables of the stress cluster: at high
    // concurrency (c > 50), RPC timeouts trigger remove_contact, leaving
    // nodes unable to find each other. Running security checks on the same
    // stressed nodes would produce spurious availability failures (Some(false),
    // get→None) that are unrelated to the security properties under test.
    //
    // Solution: fresh cluster on separate ports, bootstrapped from scratch.
    println!("\n  Spinning up isolated security cluster...");
    const SEC_SEED_PORT: u16 = 15803;
    const SEC_PEER1_PORT: u16 = 15804;
    let sec_seed = start_node(SEC_SEED_PORT).await;
    let sec_peer = start_node(SEC_PEER1_PORT).await;
    sec_peer
        .bootstrap(vec![("127.0.0.1".to_string(), SEC_SEED_PORT)])
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let sec_nodes: Vec<Arc<Server>> = vec![sec_seed, sec_peer];
    println!("  ok\n");

    println!("━━━ Phase 2: Security Invariants ━━━━━━━━━━━━━━━\n");
    let checks = run_security_checks(&sec_nodes).await;
    let total = checks.len();
    let passed = checks.iter().filter(|c| c.passed).count();

    for c in &checks {
        let mark = if c.passed { "✓" } else { "✗" };
        println!("  [{mark}] {}", c.name);
        if !c.passed || std::env::var("VERBOSE").is_ok() {
            println!("        {}", c.detail);
        }
    }

    println!("\n  Security checks : {passed}/{total} passed");

    // ─────────────────────────────────────────────────────────────────────────
    // Exit code
    // ─────────────────────────────────────────────────────────────────────────
    let security_ok = passed == total;
    let integrity_ok = corruptions == 0;
    println!();
    if security_ok && integrity_ok {
        println!("  RESULT: ALL CHECKS PASSED ✓");
    } else {
        if !integrity_ok {
            eprintln!("  RESULT: DATA INTEGRITY FAILURE ({corruptions} corruptions)");
        }
        if !security_ok {
            eprintln!(
                "  RESULT: SECURITY FAILURE ({}/{total} checks failed)",
                total - passed
            );
        }
        std::process::exit(1);
    }
}
