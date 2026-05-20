//! Cache vs no-cache benchmark for AuthKademlia-RS.
//!
//! Spins up two identical 3-node clusters on loopback:
//!   - Cluster A: `use_cache = true`  (shared `Arc<SignatureCache>`)
//!   - Cluster B: `use_cache = false` (full Dilithium-2 re-verification every time)
//!
//! Runs the same synthetic workload against both clusters and measures:
//!   - SET latency          — store a fresh signed DID Document
//!   - Cold GET latency     — first read (signature verification always runs)
//!   - Warm GET latency     — second read of the same key
//!                            (cache: SHA-256 lookup; no-cache: Dilithium-2 re-verify)
//!
//! The warm-GET column is the primary signal: it isolates the pure cost of
//! Dilithium-2 verification that the cache eliminates.
//!
//! Run:
//!   cargo run --release --example cache_bench
//!   cargo run --release --example cache_bench -- 300 25   # ops concurrency

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
use pqcrypto_traits::sign::PublicKey as SignPublicKey;
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::timeout;
use uuid::Uuid;

// ── Port allocations (must not overlap with any other test/example) ───────────
const CACHED_SEED: u16 = 15810;
const CACHED_PEER1: u16 = 15811;
const CACHED_PEER2: u16 = 15812;
const UNCACHED_SEED: u16 = 15813;
const UNCACHED_PEER1: u16 = 15814;
const UNCACHED_PEER2: u16 = 15815;

const DEFAULT_OPS: usize = 200;
const DEFAULT_CONCURRENCY: usize = 20;
const OP_TIMEOUT: Duration = Duration::from_secs(15);

// ── Latency helpers ───────────────────────────────────────────────────────────

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

// ── DID / record helpers ──────────────────────────────────────────────────────

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

fn build_signed_record(did: &str, dpk: &dilithium2::PublicKey, dsk: &dilithium2::SecretKey, kpk: &kyber512::PublicKey) -> (String, Vec<u8>) {
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = json!({
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
        "keyAgreement":   [format!("{}#k1", did)],
        "service": [{ "id": format!("{}#device", did), "type": "DeviceAgent",
                      "serviceEndpoint": "http://example.com/device" }]
    });
    let doc_bytes = serde_json::to_vec(&sort_json_keys(&doc)).expect("serialize");
    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");
    let sig = dilithium2::detached_sign(&doc_bytes, dsk);
    let sig_bytes = <dilithium2::DetachedSignature as pqcrypto_traits::sign::DetachedSignature>::as_bytes(&sig);
    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    (key, record)
}

fn new_record() -> (String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _)   = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    build_signed_record(&did, &dpk, &dsk, &kpk)
}

// ── Cluster factory ───────────────────────────────────────────────────────────

async fn start_cluster(seed: u16, peer1: u16, peer2: u16, use_cache: bool) -> Vec<Arc<Server>> {
    let make = |port: u16| {
        let use_cache = use_cache;
        async move {
            let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from("issuer.bin")));
            let mut srv = Server::new(handler, 20, 3, None, None, use_cache);
            srv.listen(port, "127.0.0.1").await.expect("listen failed");
            Arc::new(srv)
        }
    };

    let s  = make(seed).await;
    let p1 = make(peer1).await;
    let p2 = make(peer2).await;

    p1.bootstrap(vec![("127.0.0.1".to_string(), seed)]).await;
    p2.bootstrap(vec![("127.0.0.1".to_string(), seed)]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    vec![s, p1, p2]
}

// ── Workload ──────────────────────────────────────────────────────────────────

/// Collected latencies and counters for one cluster run.
struct Results {
    set_ns:       Vec<u64>,
    cold_get_ns:  Vec<u64>,
    warm_get_ns:  Vec<u64>,
    set_ok:       usize,
    get_ok:       usize,
    failures:     usize,
    wall_secs:    f64,
}

/// One SET → cold-GET → warm-GET round on `writer`/`reader`.
/// Returns `(set_ns, cold_ns, warm_ns)` or an error label.
async fn bench_op(
    writer: Arc<Server>,
    reader: Arc<Server>,
) -> Result<(u64, u64, u64), &'static str> {
    let (key, record) = new_record();

    let t0 = Instant::now();
    let ok = timeout(OP_TIMEOUT, writer.set(&key, record.clone()))
        .await
        .map_err(|_| "set timeout")?;
    let set_ns = t0.elapsed().as_nanos() as u64;
    if ok != Some(true) {
        return Err("set failed");
    }

    // Cold GET: signature cache empty for this record.
    let t1 = Instant::now();
    timeout(OP_TIMEOUT, reader.get(&key))
        .await
        .map_err(|_| "cold-get timeout")?
        .ok_or("cold-get None")?;
    let cold_ns = t1.elapsed().as_nanos() as u64;

    // Warm GET: cache case → SHA-256 lookup; no-cache → full re-verify.
    let t2 = Instant::now();
    timeout(OP_TIMEOUT, reader.get(&key))
        .await
        .map_err(|_| "warm-get timeout")?
        .ok_or("warm-get None")?;
    let warm_ns = t2.elapsed().as_nanos() as u64;

    Ok((set_ns, cold_ns, warm_ns))
}

async fn run_workload(nodes: &[Arc<Server>], num_ops: usize, concurrency: usize) -> Results {
    let set_ns      = Arc::new(Mutex::new(Vec::<u64>::with_capacity(num_ops)));
    let cold_get_ns = Arc::new(Mutex::new(Vec::<u64>::with_capacity(num_ops)));
    let warm_get_ns = Arc::new(Mutex::new(Vec::<u64>::with_capacity(num_ops)));
    let set_ok      = Arc::new(AtomicUsize::new(0));
    let get_ok      = Arc::new(AtomicUsize::new(0));
    let failures    = Arc::new(AtomicUsize::new(0));
    let done        = Arc::new(AtomicUsize::new(0));
    let sem         = Arc::new(Semaphore::new(concurrency));

    let wall = Instant::now();
    let mut handles = Vec::with_capacity(num_ops);

    for i in 0..num_ops {
        let writer = Arc::clone(&nodes[i % nodes.len()]);
        let reader = Arc::clone(&nodes[(i + 1) % nodes.len()]);
        let sem    = Arc::clone(&sem);
        let set_ns      = Arc::clone(&set_ns);
        let cold_get_ns = Arc::clone(&cold_get_ns);
        let warm_get_ns = Arc::clone(&warm_get_ns);
        let set_ok  = Arc::clone(&set_ok);
        let get_ok  = Arc::clone(&get_ok);
        let fail    = Arc::clone(&failures);
        let done    = Arc::clone(&done);

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire_owned().await.unwrap();
            match bench_op(writer, reader).await {
                Ok((s, c, w)) => {
                    set_ok.fetch_add(1, Ordering::Relaxed);
                    get_ok.fetch_add(1, Ordering::Relaxed);
                    set_ns.lock().await.push(s);
                    cold_get_ns.lock().await.push(c);
                    warm_get_ns.lock().await.push(w);
                }
                Err(_) => {
                    fail.fetch_add(1, Ordering::Relaxed);
                }
            }
            let n    = done.fetch_add(1, Ordering::Relaxed) + 1;
            let step = (num_ops / 10).max(1);
            if n % step == 0 || n == num_ops {
                print!("\r    {n}/{num_ops}");
                use std::io::Write;
                let _ = std::io::stdout().flush();
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let wall_secs = wall.elapsed().as_secs_f64();
    println!("\r    {num_ops}/{num_ops}  ✓        ");

    let mut set_v  = set_ns.lock().await.clone();
    let mut cold_v = cold_get_ns.lock().await.clone();
    let mut warm_v = warm_get_ns.lock().await.clone();
    set_v.sort_unstable();
    cold_v.sort_unstable();
    warm_v.sort_unstable();

    Results {
        set_ns:    set_v,
        cold_get_ns: cold_v,
        warm_get_ns: warm_v,
        set_ok:    set_ok.load(Ordering::Relaxed),
        get_ok:    get_ok.load(Ordering::Relaxed),
        failures:  failures.load(Ordering::Relaxed),
        wall_secs,
    }
}

// ── Reporting ─────────────────────────────────────────────────────────────────

fn print_table(label: &str, r: &Results, num_ops: usize) {
    let tp = num_ops as f64 / r.wall_secs;
    println!("  Label        : {label}");
    println!("  Throughput   : {tp:.1} ops/s  (wall {:.2}s)", r.wall_secs);
    println!("  ok / fail    : {} set  {} get  {} fail",
             r.set_ok, r.get_ok, r.failures);
    println!();
    println!("  ┌───────────────┬──────────┬──────────┬──────────┬──────────┬──────────┐");
    println!("  │               │   avg    │   p50    │   p95    │   p99    │   max    │");
    println!("  ├───────────────┼──────────┼──────────┼──────────┼──────────┼──────────┤");
    for (lbl, v) in [("SET", &r.set_ns), ("GET cold", &r.cold_get_ns), ("GET warm", &r.warm_get_ns)] {
        if v.is_empty() {
            println!("  │ {lbl:<13} │   n/a    │   n/a    │   n/a    │   n/a    │   n/a    │");
        } else {
            println!(
                "  │ {:<13} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │ {:>8} │",
                lbl,
                fmt_dur(avg_ns(v) as u64),
                fmt_dur(percentile(v, 50.0)),
                fmt_dur(percentile(v, 95.0)),
                fmt_dur(percentile(v, 99.0)),
                fmt_dur(*v.last().unwrap_or(&0)),
            );
        }
    }
    println!("  └───────────────┴──────────┴──────────┴──────────┴──────────┴──────────┘");
}

fn print_comparison(cached: &Results, uncached: &Results) {
    println!("  ┌───────────────┬──────────────────┬──────────────────┬────────────┐");
    println!("  │               │  cached (avg)    │ uncached (avg)   │  speedup   │");
    println!("  ├───────────────┼──────────────────┼──────────────────┼────────────┤");
    for (lbl, ca, un) in [
        ("SET",      &cached.set_ns,      &uncached.set_ns),
        ("GET cold", &cached.cold_get_ns, &uncached.cold_get_ns),
        ("GET warm", &cached.warm_get_ns, &uncached.warm_get_ns),
    ] {
        let ca_avg = avg_ns(ca);
        let un_avg = avg_ns(un);
        let speedup = if ca_avg > 0.0 { un_avg / ca_avg } else { 0.0 };
        println!(
            "  │ {:<13} │ {:>16} │ {:>16} │ {:>9.1}× │",
            lbl,
            fmt_dur(ca_avg as u64),
            fmt_dur(un_avg as u64),
            speedup,
        );
    }
    println!("  └───────────────┴──────────────────┴──────────────────┴────────────┘");
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let num_ops:     usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_OPS);
    let concurrency: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_CONCURRENCY);

    println!("╔═══════════════════════════════════════════════════╗");
    println!("║   AuthKademlia-RS  Signature Cache Benchmark      ║");
    println!("╚═══════════════════════════════════════════════════╝");
    println!("  Ops / concurrency : {num_ops} / {concurrency}");
    println!("  Record size       : ~6 KB  (Dilithium-2 + Kyber-512 DID Document)");
    println!("  Timeout / op      : {}s\n", OP_TIMEOUT.as_secs());

    // ── Spin up clusters ──────────────────────────────────────────────────────
    print!("Starting cluster A (cached)   ... ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let cached_nodes = start_cluster(CACHED_SEED, CACHED_PEER1, CACHED_PEER2, true).await;
    println!("ok  (ports {CACHED_SEED}-{CACHED_PEER2})");

    print!("Starting cluster B (uncached) ... ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let uncached_nodes = start_cluster(UNCACHED_SEED, UNCACHED_PEER1, UNCACHED_PEER2, false).await;
    println!("ok  (ports {UNCACHED_SEED}-{UNCACHED_PEER2})\n");

    // ── Run identical workloads ───────────────────────────────────────────────
    println!("━━━ Cluster A (cached) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let cached_results = run_workload(&cached_nodes, num_ops, concurrency).await;
    println!();
    print_table("with cache", &cached_results, num_ops);

    println!("\n━━━ Cluster B (uncached) ━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let uncached_results = run_workload(&uncached_nodes, num_ops, concurrency).await;
    println!();
    print_table("no cache", &uncached_results, num_ops);

    // ── Side-by-side comparison ───────────────────────────────────────────────
    println!("\n━━━ Comparison ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    print_comparison(&cached_results, &uncached_results);

    // Warm-GET is the definitive cache signal.
    let cold_c = avg_ns(&cached_results.cold_get_ns);
    let cold_u = avg_ns(&uncached_results.cold_get_ns);
    let warm_c = avg_ns(&cached_results.warm_get_ns);
    let warm_u = avg_ns(&uncached_results.warm_get_ns);

    println!("\n  Key findings:");
    if cold_c > 0.0 && cold_u > 0.0 {
        let ratio = cold_u / cold_c;
        println!(
            "  • Cold GET speedup  : {ratio:.1}×  ({} cached  vs  {} uncached)",
            fmt_dur(cold_c as u64), fmt_dur(cold_u as u64)
        );
        println!("    (cold path always runs full Dilithium-2 — difference is overhead only)");
    }
    if warm_c > 0.0 && warm_u > 0.0 {
        let ratio = warm_u / warm_c;
        println!(
            "  • Warm GET speedup  : {ratio:.1}×  ({} cached  vs  {} uncached)",
            fmt_dur(warm_c as u64), fmt_dur(warm_u as u64)
        );
        println!("    (cached path: SHA-256 key lookup;  uncached: full Dilithium-2 re-verify)");
    }
}
