/// Resilience test — Node A (victim / seed).
///
/// Seeds SEED_COUNT valid DID records directly into local storage, then stays
/// alive accepting incoming RPCs. Designed to be flooded by `resilience_attacker`.
///
/// Environment variables:
///   NODE_PORT   — UDP port (default: 5678)
///   SEED_COUNT  — records to pre-seed (default: 5)
///   RUST_LOG    — log level (default: info)
///
/// Run standalone:
///   cargo run --release --bin resilience_victim
///
/// Run via Docker:
///   docker compose -f resilience/docker-compose.yaml up
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;
use auth_kademlia_rs::storage::IStorage;
use auth_kademlia_rs::utils::digest;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::kem::PublicKey as KemPublicKey;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use serde_json::{json, Value};
use uuid::Uuid;

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

/// Build a valid self-signed DID record (wire format: alg || sig || doc_json).
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port: u16 = std::env::var("NODE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5678);

    let seed_count: usize = std::env::var("SEED_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);

    println!("╔══════════════════════════════════════════════╗");
    println!("║     AuthKademlia-RS  Resilience Victim       ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("  Port        : {port}");
    println!("  Seed records: {seed_count}");
    println!();

    let issuer_path = PathBuf::from("issuer.bin");
    if !issuer_path.exists() {
        log::warn!(
            "issuer.bin not found — STATUS_LIST_KEY verification disabled. \
             Normal DID record operations unaffected."
        );
    }

    let handler = Arc::new(DIDSignatureVerifierHandler::new(issuer_path));
    let mut server = Server::new(handler, 20, 3, None, None, true);
    server
        .listen(port, "0.0.0.0")
        .await
        .expect("failed to bind UDP socket");

    println!("[victim] Listening on 0.0.0.0:{port}");

    // Seed records directly into local storage.
    // The node is alone at startup (no peers yet), so calling server.set()
    // would fail because set_digest() requires at least one reachable neighbor.
    // Direct storage insertion bypasses the DHT layer — correct for a seed node.
    println!("[victim] Seeding {seed_count} records into local storage...");

    // Generate keypairs in a blocking thread (CPU-intensive, ~10ms per record).
    let records: Vec<(String, Vec<u8>)> =
        tokio::task::spawn_blocking(move || (0..seed_count).map(|_| make_record()).collect())
            .await
            .unwrap();

    for (i, (key, record)) in records.iter().enumerate() {
        let dkey = digest(key);
        server.storage.set(dkey.to_vec(), record.clone());
        println!(
            "[victim]   record {}/{} stored  key={}…",
            i + 1,
            seed_count,
            &key[..8]
        );
    }

    println!("[victim] READY — {seed_count} records seeded. Awaiting incoming attack.\n");

    // Periodic health ticker: prints storage size every 30 s so Docker logs
    // show that Node A is alive and responsive even under load.
    let storage_ref = Arc::clone(&server.storage);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let count = storage_ref.iter_all().len();
            println!("[victim] [health] storage={count} records — node alive");
        }
    });

    // Wait for SIGTERM (Docker stop) or SIGINT (Ctrl-C).
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler failed");
        tokio::select! {
            _ = sigterm.recv()           => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }

    println!("[victim] Shutdown signal received — stopping.");
    server.stop().await;
    println!("[victim] Stopped.");
}
