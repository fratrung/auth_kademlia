
use std::sync::Arc;
use std::path::PathBuf;

use auth_kademlia::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia::network::Server;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey};

// ─── Encoding / JSON ──────────────────────────────────────────────────────────
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

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

#[cfg(test)]
mod tests {
    use super::*; // Importa le funzioni di utilità che hai già scritto
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_dht_publish_and_retrieve() {
        // 1. Inizializza 3 nodi su porte diverse
        let mut nodes = Vec::new();
        let ports = [5678, 5679, 5680];

        for port in &ports {
            let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from("issuer_pub_key.bin")));
            let mut server = Server::new(handler, 20, 3, None, None);
            server.listen(*port, "127.0.0.1").await.unwrap();
            nodes.push(server);
        }

        // 2. Bootstrap: nodo B(5679) e C(5680) si connettono ad A(5678)
        nodes[1].bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;
        nodes[2].bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;
        
        // Attendi un momento che la rete si stabilizzi
        sleep(Duration::from_secs(1)).await;

        // 3. Genera chiavi e DID
        let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
        let (kyber_pk, _) = kyber512::keypair();
        let did = generate_did_iiot();
        let did_doc = build_did_document(&did, &dilithium_pk, &kyber_pk);
        let dht_key = did.split(':').last().unwrap().to_string();

        // 4. Pubblica dal nodo B
        let signed_record = build_signed_record(&did_doc, &dilithium_sk, "Dilithium-2");
        let store_result = nodes[1].set(&dht_key.clone(), signed_record).await;
        assert!(store_result.unwrap_or(false), "Il salvataggio dovrebbe avere successo");

        // 5. Recupera dal nodo C
        let retrieved = nodes[2].get(&dht_key).await;
        assert!(retrieved.is_some(), "Il record dovrebbe essere presente nella DHT");
        
        println!("Test completato con successo!");
    }
}