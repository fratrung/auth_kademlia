//! Topology test for AuthKademlia-RS.
//!
//! Launches 8 nodes with a small k=3 so records are NOT replicated everywhere.
//! This forces real multi-hop DHT lookups when a node requests a record it does
//! not hold locally, making the performance numbers representative of a real
//! (non-trivial) network.
//!
//! After publishing 30 records from random writer nodes and retrieving them
//! from randomly chosen reader nodes, the test prints:
//!
//!   - Performance summary (SET / GET latencies, throughput)
//!   - Per-node storage table (DHT keys stored on that node)
//!   - Per-node routing table (all peers the node knows about)
//!
//! Run:
//!   cargo run --release --example topology_test                     # defaults: k=20 alpha=3
//!   cargo run --release --example topology_test -- 3 3              # k=3  alpha=3
//!   cargo run --release --example topology_test -- 5 2              # k=5  alpha=2
//!   RUST_LOG=info cargo run --release --example topology_test -- 3  # with DHT logs

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::IStorage;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::PublicKey;
use serde_json::{json, Value};
use tokio::time::timeout;
use uuid::Uuid;

// ─── Topology parameters ─────────────────────────────────────────────────────

/// First port of the 8-node cluster (15810–15817).
const BASE_PORT: u16 = 15810;
const NUM_NODES: usize = 30;
/// Small k so records are stored only on the 3 closest nodes, forcing real lookups.
const KSIZE: usize = 20;
const ALPHA: usize = 3;

const NUM_RECORDS: usize = 200;
const OP_TIMEOUT: Duration = Duration::from_secs(10);

// ─── Record helpers ───────────────────────────────────────────────────────────

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

/// Returns (did_uri, dht_key, record_bytes).
fn new_record() -> (String, String, Vec<u8>) {
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = format!("did:iiot:{}", Uuid::new_v4());
    let key = did.split(':').next_back().unwrap().to_string();
    let doc = build_did_document(&did, &dpk, &kpk);
    let record = build_signed_record(&doc, &dsk);
    (did, key, record)
}

/// Extract the DID Document JSON from a raw record (skip alg + signature header).
fn extract_doc(record: &[u8]) -> Option<serde_json::Value> {
    // Wire format: [alg 12 B][Dilithium-2 sig 2420 B][DID Document JSON]
    const SIG_LEN: usize = 2420;
    let doc_start = 12 + SIG_LEN;
    if record.len() <= doc_start {
        return None;
    }
    serde_json::from_slice(&record[doc_start..]).ok()
}

// ─── Node factory ─────────────────────────────────────────────────────────────

async fn start_node(port: u16) -> Arc<Server> {
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from("issuer.bin")));
    let mut server = Server::new(handler, KSIZE, ALPHA, None, None);
    server.listen(port, "127.0.0.1").await.expect("listen failed");
    Arc::new(server)
}

// ─── Topology inspector ───────────────────────────────────────────────────────

async fn print_topology(
    nodes: &[(Arc<Server>, u16)],
    key_to_did: &HashMap<String, String>,
    sample_records: &[(String, Vec<u8>)], // (did_uri, record) — printed as DID Documents
) {
    // ── Sample DID Documents ──────────────────────────────────────────────────
    println!("━━━ Sample DID Documents ━━━━━━━━━━━━━━━━━━━━━━━\n");
    for (did, record) in sample_records {
        println!("  DID URI : {did}");
        println!("  DHT key : {}", {
            let uuid = did.split(':').next_back().unwrap_or("");
            let digest = auth_kademlia_rs::utils::digest(uuid);
            hex::encode(digest)
        });
        match extract_doc(record) {
            Some(doc) => {
                let pretty = serde_json::to_string_pretty(&doc).unwrap_or_default();
                for line in pretty.lines() {
                    println!("  {line}");
                }
            }
            None => println!("  (could not parse DID Document)"),
        }
        println!();
    }

    println!("━━━ Storage Tables (keys stored per node) ━━━━━━\n");

    // Build a key→port map: which nodes hold which key (for cross-reference)
    let mut key_holders: HashMap<String, Vec<u16>> = HashMap::new();

    for (server, port) in nodes {
        let entries = server.storage.iter_all();
        let keys: Vec<String> = entries
            .iter()
            .map(|(k, _)| hex::encode(k))
            .collect();

        println!("  Node :{port}  ({} records)", keys.len());
        if keys.is_empty() {
            println!("    (empty)");
        } else {
            for k in &keys {
                let did_hint = key_to_did
                    .get(k)
                    .map(|d| format!("  →  {d}"))
                    .unwrap_or_default();
                println!("    {k}{did_hint}");
                key_holders.entry(k.clone()).or_default().push(*port);
            }
        }
        println!();
    }

    // Replication summary: how many nodes hold each key
    println!("━━━ Replication Summary ━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("  {:>64}  copies  holders", "DHT key (hex)");
    println!("  {}  ------  -------", "-".repeat(64));
    let mut sorted_keys: Vec<_> = key_holders.iter().collect();
    sorted_keys.sort_by_key(|(k, _)| k.as_str());
    for (key, holders) in &sorted_keys {
        let ports: Vec<String> = holders.iter().map(|p| p.to_string()).collect();
        println!(
            "  {key}  {:>6}  {}",
            holders.len(),
            ports.join(", ")
        );
    }
    println!();

    println!("━━━ Routing Tables (peers known per node) ━━━━━━\n");

    for (server, port) in nodes {
        let proto = match &server.protocol {
            Some(p) => p,
            None => {
                println!("  Node :{port}  (protocol not started)");
                continue;
            }
        };

        // Collect all peers from all k-buckets
        let router = proto.router.read().await;
        let mut peers: Vec<_> = router
            .buckets()
            .iter()
            .flat_map(|b| b.nodes().iter().cloned())
            .collect();
        peers.sort_by_key(|n| n.port.unwrap_or(0));

        println!("  Node :{port}  ({} known peers)", peers.len());
        if peers.is_empty() {
            println!("    (no peers)");
        } else {
            println!(
                "    {:>44}  {:>5}  {}",
                "node-id (hex, first 8 bytes)", "port", "ip"
            );
            for peer in &peers {
                let id_hex: String = peer.id[..8].iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "    {}  {:>5}  {}",
                    id_hex,
                    peer.port.map(|p| p.to_string()).unwrap_or("-".into()),
                    peer.ip.as_deref().unwrap_or("-"),
                );
            }
        }
        println!();
    }
}

// ─── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════════╗");
    println!("║     AuthKademlia-RS  Topology Test           ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  Nodes    : {NUM_NODES}  (ports {BASE_PORT}–{})", BASE_PORT + NUM_NODES as u16 - 1);
    println!("  k (ksize): {KSIZE}  → records stored on ≤{KSIZE} closest nodes only");
    println!("  Records  : {NUM_RECORDS}  published from random writers, read from random readers");
    println!("  Timeout  : {}s/op\n", OP_TIMEOUT.as_secs());

    // ── Start cluster ─────────────────────────────────────────────────────────
    print!("Starting {NUM_NODES} nodes... ");
    let mut nodes: Vec<(Arc<Server>, u16)> = Vec::with_capacity(NUM_NODES);
    for i in 0..NUM_NODES {
        let port = BASE_PORT + i as u16;
        nodes.push((start_node(port).await, port));
    }
    println!("ok");

    // ── Bootstrap: each node joins via the seed (node 0) ─────────────────────
    print!("Bootstrapping... ");
    let seed_port = BASE_PORT;
    for (server, _) in nodes.iter().skip(1) {
        server
            .bootstrap(vec![("127.0.0.1".to_string(), seed_port)])
            .await;
    }
    // Second pass: stabilize routing tables after all nodes are known
    tokio::time::sleep(Duration::from_millis(300)).await;
    for (server, _) in nodes.iter().skip(1) {
        server
            .bootstrap(vec![("127.0.0.1".to_string(), seed_port)])
            .await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    println!("ok\n");

    // ── Publish records ───────────────────────────────────────────────────────
    println!("━━━ Phase 1: Publish {NUM_RECORDS} Records ━━━━━━━━━━━━━━━━\n");

    // (did_uri, dht_key, record_bytes)
    let mut published: Vec<(String, String, Vec<u8>)> = Vec::new();
    let mut set_ok = 0usize;
    let mut set_fail = 0usize;
    let mut set_latencies: Vec<u64> = Vec::new();

    for i in 0..NUM_RECORDS {
        let (did, key, record) = new_record();
        let (writer, writer_port) = &nodes[i % NUM_NODES];

        let t0 = Instant::now();
        let result = timeout(OP_TIMEOUT, writer.set(&key, record.clone())).await;
        let ns = t0.elapsed().as_nanos() as u64;

        match result {
            Ok(Some(true)) => {
                set_ok += 1;
                set_latencies.push(ns);
                println!(
                    "  [{i:>2}] writer={writer_port}  key={}  did={}...  SET ✓  ({:.1}ms)",
                    &key[..8],
                    &did[..32],
                    ns as f64 / 1e6
                );
                published.push((did, key, record));
            }
            other => {
                set_fail += 1;
                println!("  [{i:>2}] writer={writer_port}  key={}  SET ✗  {other:?}", &key[..8]);
            }
        }
    }
    println!("\n  Published: {set_ok}/{NUM_RECORDS}  ({set_fail} failed)\n");

    // ── Retrieve records ──────────────────────────────────────────────────────
    println!("━━━ Phase 2: Retrieve Records ━━━━━━━━━━━━━━━━━━\n");
    println!("  (reader is always a different node than the expected holder — forces DHT lookup)\n");

    let mut get_ok = 0usize;
    let mut get_fail = 0usize;
    let mut get_corrupt = 0usize;
    let mut get_latencies: Vec<u64> = Vec::new();

    for (i, (_did, key, original)) in published.iter().enumerate() {
        // Choose a reader offset by half the cluster size from the writer
        let reader_idx = (i + NUM_NODES / 2) % NUM_NODES;
        let (reader, reader_port) = &nodes[reader_idx];

        let t0 = Instant::now();
        let result = timeout(OP_TIMEOUT, reader.get(key)).await;
        let ns = t0.elapsed().as_nanos() as u64;

        match result {
            Ok(Some(ref retrieved)) => {
                let ok = retrieved == original;
                get_latencies.push(ns);
                if ok {
                    get_ok += 1;
                    println!(
                        "  [{i:>2}] reader={reader_port}  key={}  GET ✓  ({:.1}ms)",
                        &key[..8], ns as f64 / 1e6
                    );
                } else {
                    get_corrupt += 1;
                    println!(
                        "  [{i:>2}] reader={reader_port}  key={}  GET ✗  CORRUPTION",
                        &key[..8]
                    );
                }
            }
            Ok(None) => {
                get_fail += 1;
                println!(
                    "  [{i:>2}] reader={reader_port}  key={}  GET ✗  not found  ({:.1}ms)",
                    &key[..8], ns as f64 / 1e6
                );
            }
            Err(_) => {
                get_fail += 1;
                println!(
                    "  [{i:>2}] reader={reader_port}  key={}  GET ✗  timeout",
                    &key[..8]
                );
            }
        }
    }

    println!("\n  Retrieved: {get_ok}/{set_ok}  ({get_fail} not found, {get_corrupt} corrupted)\n");

    // ── Latency summary ───────────────────────────────────────────────────────
    println!("━━━ Latency Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    fn stats(v: &mut Vec<u64>) -> (f64, u64, u64, u64) {
        v.sort_unstable();
        let avg = if v.is_empty() { 0.0 } else { v.iter().sum::<u64>() as f64 / v.len() as f64 };
        let p50 = percentile(v, 50.0);
        let p95 = percentile(v, 95.0);
        let max = *v.last().unwrap_or(&0);
        (avg, p50, p95, max)
    }
    fn percentile(sorted: &[u64], p: f64) -> u64 {
        if sorted.is_empty() { return 0; }
        let idx = ((sorted.len() as f64 * p / 100.0).ceil() as usize).saturating_sub(1);
        sorted[idx.min(sorted.len() - 1)]
    }
    fn fmt(ns: u64) -> String {
        if ns < 1_000_000 { format!("{:.1}µs", ns as f64 / 1_000.0) }
        else { format!("{:.1}ms", ns as f64 / 1_000_000.0) }
    }

    let (sa, sp50, sp95, smax) = stats(&mut set_latencies);
    let (ga, gp50, gp95, gmax) = stats(&mut get_latencies);

    println!("  ┌───────┬──────────┬──────────┬──────────┬──────────┐");
    println!("  │       │   avg    │   p50    │   p95    │   max    │");
    println!("  ├───────┼──────────┼──────────┼──────────┼──────────┤");
    println!("  │ SET   │ {:>8} │ {:>8} │ {:>8} │ {:>8} │", fmt(sa as u64), fmt(sp50), fmt(sp95), fmt(smax));
    println!("  │ GET   │ {:>8} │ {:>8} │ {:>8} │ {:>8} │", fmt(ga as u64), fmt(gp50), fmt(gp95), fmt(gmax));
    println!("  └───────┴──────────┴──────────┴──────────┴──────────┘\n");

    // ── Topology inspection ───────────────────────────────────────────────────
    // Build key→did_uri map and pick 3 sample records to show as full DID Documents
    let key_to_did: HashMap<String, String> = published
        .iter()
        .map(|(did, key, _)| {
            let dht_hex = hex::encode(auth_kademlia_rs::utils::digest(key.as_str()));
            (dht_hex, did.clone())
        })
        .collect();

    let samples: Vec<(String, Vec<u8>)> = published
        .iter()
        .take(3)
        .map(|(did, _, record)| (did.clone(), record.clone()))
        .collect();

    print_topology(&nodes, &key_to_did, &samples).await;

    // ── Final verdict ─────────────────────────────────────────────────────────
    println!("━━━ Result ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    if get_fail == 0 && get_corrupt == 0 && set_fail == 0 {
        println!("  ALL CHECKS PASSED ✓\n");
    } else {
        println!("  SET fail: {set_fail}  GET fail: {get_fail}  Corruptions: {get_corrupt}");
        std::process::exit(1);
    }
}
