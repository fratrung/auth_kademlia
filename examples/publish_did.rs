/// Example: publish and retrieve a signed DID Document via auth_kademlia.
///
/// Rust equivalent of the Python AuthKademlia example:
///
///   1. Start a DHT node with signature verification
///   2. Generate Dilithium + Kyber key pairs
///   3. Build a did:iiot DID Document
///   4. Sign it and pack it into the record format:
///        | algorithm (12 bytes, null-padded) | signature | DID Document (JSON) |
///   5. Store the signed record in the DHT under the DID's UUID fragment
///   6. Retrieve and verify it
///
/// To run:
///   cargo run --example publish_did -- --bootstrap 127.0.0.1:5678
///
/// If this is the first node in the network, omit --bootstrap.
use std::sync::Arc;
use std::path::PathBuf;

use auth_kademlia::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia::network::Server;

// ─── Post-quantum primitives ──────────────────────────────────────────────────
// These come from the `pqcrypto` family of crates.
// Add to Cargo.toml:
//   pqcrypto-dilithium = "0.5"
//   pqcrypto-kyber     = "0.8"
//   pqcrypto-traits    = "0.3"
use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey};

// ─── Encoding / JSON ──────────────────────────────────────────────────────────
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Record format helpers
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// DID Document builder
// ─────────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    async fn start_node(port: u16) -> Server {
        let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from("issuer.bin")));
        let mut server = Server::new(handler, 20, 3, None, None);
        server.listen(port, "127.0.0.1").await.unwrap();
        println!("Nodo avviato sulla porta {}", port);
        server
    }

    let node_1 = start_node(5678).await;
    let node_2 = start_node(5679).await;

    println!("Nodo 2: Eseguo bootstrap verso Nodo 1 (5678)...");
    node_2.bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;

    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let (kyber_pk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let did_doc = build_did_document(&did, &dilithium_pk, &kyber_pk);
    let dht_key = did.split(':').last().unwrap().to_string();

    let signed_record = build_signed_record(&did_doc, &dilithium_sk, "Dilithium-2");
    
    println!("Nodo 2: Pubblico il DID {} nella rete", dht_key);
    node_2.set(&dht_key.clone(), signed_record).await;

    println!("Nodo 1: Recupero il record {} dalla rete...", dht_key);
    match node_1.get(&dht_key).await {
        Some(record) => {
            println!("Nodo 1: Record trovato! ({} bytes)", record.len());
        },
        None => println!("Nodo 1: Record non trovato!"),
    }

    Ok(())
}
