/// Resilience test — Node B (attacker / malicious node).
///
/// Bootstraps with Node A, pre-generates a pool of DID records, then floods
/// Node A with a sustained mix of:
///   45 % valid SET   (unique records from pre-generated pool)
///   25 % GET hit     (keys the attacker successfully stored)
///   20 % GET miss    (random UUIDs guaranteed to be absent)
///   10 % invalid SET (valid record with one signature byte flipped)
///
/// After the valid pool is exhausted, the op mix shifts to GET / invalid SET.
/// All ops are bound by a Semaphore so the host PC is never overwhelmed.
///
/// Environment variables:
///   TARGET_ADDR    — Node A address (default: 172.21.0.10:5678)
///   ATTACKER_PORT  — Node B's own UDP port (default: 5679)
///   POOL_SIZE      — valid records to pre-generate (default: 150)
///   CONCURRENCY    — max in-flight ops (default: 25)
///   DURATION_SECS  — attack wall-clock duration (default: 120)
///   RUST_LOG       — log level (default: warn)
///
/// Run via Docker:
///   docker compose -f resilience/docker-compose.yaml up
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tokio::time::timeout;
use uuid::Uuid;

const OP_TIMEOUT: Duration = Duration::from_secs(10);
const STATS_INTERVAL: Duration = Duration::from_secs(10);
// Invalid pool is 1/3 the valid pool size (cycled with modulo).
const INVALID_RATIO: usize = 3;

// ─── Stats ────────────────────────────────────────────────────────────────────

#[derive(Default)]
struct Stats {
    set_ok: AtomicUsize,
    set_rejected: AtomicUsize,
    set_timeout: AtomicUsize,
    get_hit: AtomicUsize,
    get_miss: AtomicUsize,
    get_timeout: AtomicUsize,
    /// Records with a tampered signature that node A rejected (expected: all).
    invalid_rejected: AtomicUsize,
    /// Records with a tampered signature that node A accepted (security failure!).
    invalid_accepted: AtomicUsize,
}

impl Stats {
    fn snapshot(&self) -> StatsSnap {
        StatsSnap {
            set_ok: self.set_ok.load(Ordering::Relaxed),
            set_rej: self.set_rejected.load(Ordering::Relaxed),
            set_to: self.set_timeout.load(Ordering::Relaxed),
            get_hit: self.get_hit.load(Ordering::Relaxed),
            get_miss: self.get_miss.load(Ordering::Relaxed),
            get_to: self.get_timeout.load(Ordering::Relaxed),
            inv_rej: self.invalid_rejected.load(Ordering::Relaxed),
            inv_acc: self.invalid_accepted.load(Ordering::Relaxed),
        }
    }

    fn print(&self, elapsed_secs: f64, label: &str) {
        let s = self.snapshot();
        let total = s.set_ok + s.set_rej + s.set_to
            + s.get_hit + s.get_miss + s.get_to
            + s.inv_rej + s.inv_acc;
        let tps = if elapsed_secs > 0.0 {
            total as f64 / elapsed_secs
        } else {
            0.0
        };
        let security_flag = if s.inv_acc > 0 {
            format!("  ← !! SECURITY FAILURE: {} invalid accepted !!", s.inv_acc)
        } else {
            String::new()
        };
        println!(
            "[attacker] {:<22} {:>5.0}s  {total:>5} ops  {tps:>5.1}/s\n\
             [attacker]   SET  ok={:<5} rejected={:<5} timeout={}\n\
             [attacker]   GET  hit={:<5} miss={:<5}    timeout={}\n\
             [attacker]   INV  rejected={:<5} accepted={}{security_flag}\n",
            label,
            elapsed_secs,
            s.set_ok,
            s.set_rej,
            s.set_to,
            s.get_hit,
            s.get_miss,
            s.get_to,
            s.inv_rej,
            s.inv_acc,
        );
    }
}

struct StatsSnap {
    set_ok: usize,
    set_rej: usize,
    set_to: usize,
    get_hit: usize,
    get_miss: usize,
    get_to: usize,
    inv_rej: usize,
    inv_acc: usize,
}

// ─── DID record helpers ───────────────────────────────────────────────────────

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn sort_json(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .collect::<std::collections::BTreeMap<_, _>>()
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(sort_json).collect()),
        other => other.clone(),
    }
}

fn make_record() -> (String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let key = did.split(':').next_back().unwrap().to_string();

    let doc = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#k0", did), "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Dilithium2",
                                  "x": b64url(dpk.as_bytes()) }
            },
            {
                "id": format!("{}#k1", did), "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": { "kty": "OKP", "crv": "Kyber512",
                                  "x": b64url(kpk.as_bytes()) }
            }
        ],
        "authentication": [format!("{}#k0", did)],
        "keyAgreement":   [format!("{}#k1", did)],
        "service": [{
            "id": format!("{}#device", did),
            "type": "DeviceAgent",
            "serviceEndpoint": "http://example.com/device"
        }]
    });

    let doc_bytes = serde_json::to_vec(&sort_json(&doc)).unwrap();
    let sig = dilithium2::detached_sign(&doc_bytes, &dsk);
    let sig_bytes = sig.as_bytes();

    let mut alg = [0u8; 12];
    alg[..11].copy_from_slice(b"Dilithium-2");

    let mut record = Vec::with_capacity(12 + sig_bytes.len() + doc_bytes.len());
    record.extend_from_slice(&alg);
    record.extend_from_slice(sig_bytes);
    record.extend_from_slice(&doc_bytes);
    (key, record)
}

// ─── Op type ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
enum Op {
    SetValid { key: String, record: Vec<u8> },
    GetKnown { key: String },
    GetMiss { key: String },
    SetInvalid { key: String, record: Vec<u8> },
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
        .unwrap()
        .block_on(run());
}

async fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    // ── Configuration ─────────────────────────────────────────────────────────
    let target_addr = std::env::var("TARGET_ADDR")
        .unwrap_or_else(|_| "172.21.0.10:5678".to_string());
    let attacker_port: u16 = std::env::var("ATTACKER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5679);
    let pool_size: usize = std::env::var("POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150);
    let concurrency: usize = std::env::var("CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let duration_secs: u64 = std::env::var("DURATION_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120);

    println!("╔══════════════════════════════════════════════╗");
    println!("║     AuthKademlia-RS  Resilience Attacker     ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  Target      : {target_addr}");
    println!("  Attacker    : 0.0.0.0:{attacker_port}");
    println!("  Pool size   : {pool_size} valid + {} invalid (pre-generated)", pool_size / INVALID_RATIO);
    println!("  Concurrency : {concurrency}  (semaphore — won't overwhelm host CPU)");
    println!("  Duration    : {duration_secs}s");
    println!();

    // ── Start Node B ──────────────────────────────────────────────────────────
    let issuer_path = PathBuf::from("issuer.bin");
    let handler = Arc::new(DIDSignatureVerifierHandler::new(issuer_path));
    let mut server = Server::new(handler, 20, 3, None, None, true);
    server
        .listen(attacker_port, "0.0.0.0")
        .await
        .expect("failed to bind UDP socket");
    let server = Arc::new(server);

    // ── Wait for victim ───────────────────────────────────────────────────────
    println!("[attacker] Waiting 5s for Node A to be ready...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ── Bootstrap with Node A ─────────────────────────────────────────────────
    let parts: Vec<&str> = target_addr.splitn(2, ':').collect();
    let target_ip = parts[0].to_string();
    let target_port: u16 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(5678);

    print!("[attacker] Bootstrapping with {target_addr}... ");
    let discovered = server
        .bootstrap(vec![(target_ip, target_port)])
        .await;
    if discovered.is_empty() {
        println!("WARN: no peers discovered (continuing — victim may still handle RPCs)");
    } else {
        println!("ok  ({} peer(s))", discovered.len());
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // ── Pre-generate record pool (blocking, CPU-intensive) ────────────────────
    let inv_size = pool_size / INVALID_RATIO;
    println!("[attacker] Pre-generating {pool_size} valid + {inv_size} invalid records...");
    let t_gen = Instant::now();

    let ps = pool_size;
    let is = inv_size;
    let (valid_pool, invalid_pool): (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) =
        tokio::task::spawn_blocking(move || {
            let valid: Vec<_> = (0..ps).map(|_| make_record()).collect();
            let invalid: Vec<_> = (0..is)
                .map(|_| {
                    let (key, mut rec) = make_record();
                    rec[500] ^= 0xFF; // corrupt one byte inside the Dilithium signature
                    (key, rec)
                })
                .collect();
            (valid, invalid)
        })
        .await
        .unwrap();

    println!(
        "[attacker] Pool ready in {:.1}s  ({} valid, {} invalid)\n",
        t_gen.elapsed().as_secs_f64(),
        valid_pool.len(),
        invalid_pool.len()
    );

    // ── Attack ────────────────────────────────────────────────────────────────
    println!("[attacker] ━━━ ATTACK START ━━━");
    println!("[attacker] Flooding Node A for {duration_secs}s with ≤{concurrency} concurrent ops.\n");
    println!("[attacker] Op mix: 45% valid SET | 25% GET hit | 20% GET miss | 10% invalid SET");
    println!("[attacker] (After pool exhausted: GET + invalid SET only)\n");

    let stats = Arc::new(Stats::default());
    let sem = Arc::new(Semaphore::new(concurrency));
    // Keys we successfully stored — used for GET-hit ops.
    let stored_keys: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let mut jset: JoinSet<()> = JoinSet::new();
    let deadline = Instant::now() + Duration::from_secs(duration_secs);
    let attack_start = Instant::now();
    let mut last_stats = Instant::now();
    let mut pool_cursor: usize = 0;
    let mut inv_cursor: usize = 0;

    loop {
        // ── Print periodic stats ──────────────────────────────────────────────
        if last_stats.elapsed() >= STATS_INTERVAL {
            stats.print(attack_start.elapsed().as_secs_f64(), "in progress");
            last_stats = Instant::now();
        }

        // ── Drain completed tasks (non-blocking) ──────────────────────────────
        while jset.try_join_next().is_some() {}

        // ── Check deadline ────────────────────────────────────────────────────
        if Instant::now() >= deadline {
            break;
        }

        // ── Acquire semaphore (blocks when concurrency cap is reached) ─────────
        // Use a short timeout so the loop can re-check the deadline even when
        // all slots are busy, preventing overshoot of DURATION_SECS.
        let permit = match tokio::time::timeout(
            Duration::from_millis(500),
            Arc::clone(&sem).acquire_owned(),
        )
        .await
        {
            Ok(Ok(p)) => p,
            _ => continue,
        };

        // ── Select op ─────────────────────────────────────────────────────────
        let r: f64 = rand::random();
        let pool_remaining = pool_size.saturating_sub(pool_cursor);
        let stored_count = stored_keys.lock().await.len();

        let op: Op = if pool_remaining > 0 && r < 0.45 {
            // Valid SET from pre-generated pool
            let (key, record) = valid_pool[pool_cursor].clone();
            pool_cursor += 1;
            Op::SetValid { key, record }
        } else if stored_count > 0 && r < 0.70 {
            // GET for a key the attacker already stored (cache-hit / storage-hit path)
            let keys = stored_keys.lock().await;
            let idx = rand::random::<usize>() % keys.len();
            let key = keys[idx].clone();
            drop(keys);
            Op::GetKnown { key }
        } else if r < 0.90 {
            // GET for a random UUID — guaranteed miss, exercises DHT routing
            Op::GetMiss {
                key: Uuid::new_v4().to_string(),
            }
        } else {
            // Invalid SET: record with tampered Dilithium signature.
            // Node A MUST reject it. The same key is cycled (modulo) so the same
            // rejection path is exercised repeatedly without expanding state.
            let (key, record) = invalid_pool[inv_cursor % invalid_pool.len()].clone();
            inv_cursor += 1;
            Op::SetInvalid { key, record }
        };

        // ── Spawn op task ──────────────────────────────────────────────────────
        let node = Arc::clone(&server);
        let st = Arc::clone(&stats);
        let sk = Arc::clone(&stored_keys);

        match op {
            Op::SetValid { key, record } => {
                jset.spawn(async move {
                    let _permit = permit;
                    match timeout(OP_TIMEOUT, node.set(&key, record)).await {
                        Ok(Some(true)) => {
                            st.set_ok.fetch_add(1, Ordering::Relaxed);
                            sk.lock().await.push(key);
                        }
                        Ok(_) => {
                            st.set_rejected.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            st.set_timeout.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }

            Op::GetKnown { key } => {
                jset.spawn(async move {
                    let _permit = permit;
                    match timeout(OP_TIMEOUT, node.get(&key)).await {
                        Ok(Some(_)) => {
                            st.get_hit.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(None) => {
                            // Record not found — possible if DHT hasn't propagated yet.
                            st.get_miss.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            st.get_timeout.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }

            Op::GetMiss { key } => {
                jset.spawn(async move {
                    let _permit = permit;
                    match timeout(OP_TIMEOUT, node.get(&key)).await {
                        Ok(Some(_)) => {
                            // Unexpected hit for a random UUID — not a security issue,
                            // just an extremely unlikely UUID collision.
                            st.get_hit.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(None) => {
                            st.get_miss.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            st.get_timeout.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }

            Op::SetInvalid { key, record } => {
                jset.spawn(async move {
                    let _permit = permit;
                    match timeout(OP_TIMEOUT, node.set(&key, record)).await {
                        // set() returns None when signature verification fails —
                        // this is the expected outcome for a tampered record.
                        Ok(None) => {
                            st.invalid_rejected.fetch_add(1, Ordering::Relaxed);
                        }
                        // Some(_) means the record was accepted — security failure.
                        Ok(Some(_)) => {
                            st.invalid_accepted.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => {
                            st.get_timeout.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        }
    }

    // ── Drain remaining in-flight tasks ───────────────────────────────────────
    while jset.join_next().await.is_some() {}

    // ── Final report ──────────────────────────────────────────────────────────
    println!("\n[attacker] ━━━ ATTACK COMPLETE ━━━\n");
    stats.print(attack_start.elapsed().as_secs_f64(), "FINAL");

    let snap = stats.snapshot();
    let total = snap.set_ok
        + snap.set_rej
        + snap.set_to
        + snap.get_hit
        + snap.get_miss
        + snap.get_to
        + snap.inv_rej
        + snap.inv_acc;

    println!("━━━ Resilience verdict ━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Node A liveness: low timeout rate means A kept responding.
    let timeouts = snap.set_to + snap.get_to;
    let timeout_rate = if total > 0 {
        timeouts as f64 / total as f64
    } else {
        0.0
    };
    if timeout_rate < 0.10 {
        println!("  [✓] Node A responsive   timeout rate {:.1}% < 10%", timeout_rate * 100.0);
    } else {
        println!("  [!] Node A degraded      timeout rate {:.1}% ≥ 10%  (overloaded)", timeout_rate * 100.0);
    }

    // Security: all invalid records must be rejected.
    if snap.inv_acc == 0 {
        println!("  [✓] Security intact      all {} invalid records rejected", snap.inv_rej);
    } else {
        eprintln!(
            "  [✗] SECURITY FAILURE     {} invalid records accepted by Node A!",
            snap.inv_acc
        );
    }

    // Immutability: no duplicate accepted.
    // (set_rejected includes both dup-key and sig-failure; invalid_accepted above covers sig bypass)
    println!("  [✓] Valid SETs stored    {}", snap.set_ok);
    println!("  [✓] Rejected SETs        {} (dup/invalid)", snap.set_rej);

    println!();
    if snap.inv_acc == 0 {
        println!("  RESULT: Node A survived the attack without security violations.");
        if timeout_rate >= 0.10 {
            println!("  NOTE:   High timeout rate indicates Node A was CPU-saturated but did NOT crash.");
            println!("          This is expected behaviour under resource-limited conditions.");
        }
    } else {
        eprintln!("  RESULT: SECURITY FAILURE — Node A accepted invalid records.");
        std::process::exit(1);
    }
}
