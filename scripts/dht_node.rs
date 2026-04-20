
use std::sync::Arc;
use std::path::PathBuf;

use auth_kademlia_rs::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia_rs::network::Server;


use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

fn base64url_encode(pk: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(pk)
}

/// Serialize a DID Document to canonical JSON bytes (sorted keys, no spaces).
fn encode_did_document(doc: &Value) -> Vec<u8> {
    let canonical = sort_json_keys(doc);
    serde_json::to_vec(&canonical).expect("DID Document serialization failed")
}

fn decode_signed_record(record: Vec<u8>) -> Option<(String, Vec<u8>)> {
    if record.len() <= 12 { return None; }
    
    let sig_len = 2420; // Dilithium2 Signature length
    if record.len() < 12 + sig_len { return None; }
    
    let json_bytes = &record[12 + sig_len..];
    let doc: Value = serde_json::from_slice(json_bytes).ok()?;
    
    Some((serde_json::to_string_pretty(&doc).unwrap(), json_bytes.to_vec()))
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

    let detached_sig = dilithium2::detached_sign(&doc_bytes, secret_key);
    let signature = detached_sig.as_bytes();

    let mut record = Vec::with_capacity(12 + signature.len() + doc_bytes.len());
    record.extend_from_slice(&alg_field);
    record.extend_from_slice(signature);
    record.extend_from_slice(&doc_bytes);
    record
}

fn generate_did_iiot() -> String {
    format!("did:iiot:{}", Uuid::new_v4())
}

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
    server.listen(port, "0.0.0.0").await.unwrap();
    println!(">>> Node started on port {}", port);
    server
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    let port: u16 = std::env::var("NODE_PORT").unwrap_or_else(|_| "5678".to_string()).parse()?;
    let mut server = start_node(port).await;

    if std::env::var("IS_SEED").is_ok() {
        println!(">>> Running as Seed Node. Ready.");
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    } else if let Ok(bootstrap_addr) = std::env::var("BOOTSTRAP_ADDR") {
        let parts: Vec<&str> = bootstrap_addr.split(':').collect();
        let ip = parts[0].to_string();
        let port: u16 = parts[1].parse()?;
        
        println!(">>> Bootstrapping to {}:{}...", ip, port);
        let mut retries = 0;
        while retries < 5 {
            let discovered = server.bootstrap(vec![(ip.clone(), port)]).await;
            if !discovered.is_empty() {
                println!(">>> Bootstrap success! Discovered {} nodes.", discovered.len());
                break;
            }
            println!(">>> Bootstrap empty, retrying...");
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            retries += 1;
        }
    }

    println!(">>> Starting publication process...");
    
    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let (kyber_pk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let dht_key = did.split(':').last().unwrap().to_string();
    let signed_record = build_signed_record(&build_did_document(&did, &dilithium_pk, &kyber_pk), &dilithium_sk, "Dilithium-2");

    let mut attempt = 0;
    while attempt < 10 {
        match server.set(&dht_key, signed_record.clone()).await {
            Some(true) => {
                println!(">>> SUCCESS: DID Document published!");
                break;
            }
            _ => {
                println!(">>> Attempt {}/10 failed, retrying...", attempt + 1);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                attempt += 1;
            }
        }
    }

    println!(">>> Testing retrieval for key: {}", dht_key);
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    match server.get(&dht_key).await {
        Some(record) => {
            println!(">>> SUCCESS: Record found in DHT!");
            if let Some((json_str, _)) = decode_signed_record(record) {
                println!(">>> Decoded DID Document:\n{}", json_str);
            } else {
                println!(">>> ERROR: Could not decode record structure.");
            }
        }
        None => println!(">>> ERROR: Record not found in DHT."),
    }

    println!(">>> Node active and listening for DHT requests.");

    tokio::signal::ctrl_c().await?;
    
    println!("\n>>> Shutdown signal received. Cleaning up...");
    server.stop().await;

    println!(">>> Node stopped gracefully.");
    Ok(())
}