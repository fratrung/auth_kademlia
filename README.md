# AuthKademlia-RS

A Rust reimplementation of [AuthKademlia](https://github.com/fratrung/AuthKademlia) — an extended Kademlia Distributed Hash Table with native support for **signed records** and **Verifiable Data Registry (VDR)** capabilities for Decentralized Identifiers (DIDs).

-----

## Overview

AuthKademlia-RS is a high-performance, asynchronous implementation of the [Kademlia DHT protocol](http://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf) written in Rust. It extends the standard Kademlia specification with cryptographic record signing, making it suitable for use as a decentralized identity infrastructure layer.

Unlike conventional DHT implementations, AuthKademlia-RS treats stored values as **verifiable artifacts**: each record is cryptographically bound to its author and can be independently verified by any node in the network — without any central authority.

-----

## Key Differentiators

|Feature                  |Standard Kademlia|AuthKademlia-RS                     |
|-------------------------|-----------------|------------------------------------|
|Record integrity         |None             |Cryptographic signature verification|
|Identity support         |None             |Native DID Document storage         |
|Post-quantum cryptography|None             |Dilithium & Kyber key support       |
|Verifiable Data Registry |None             |Built-in VDR semantics              |
|Language                 |Various          |Rust (memory-safe, high-performance)|

-----

## Signed Records and Verifiable Data Registry

Each value stored in the DHT is a **structured signed record** with the following layout:

```
algorithm (12 bytes) | signature | DID Document (canonical JSON)
```

This structure allows any peer to:

- Verify the **authenticity** of stored data using the public key embedded in the DID Document
- Verify the **integrity** of the record against its signature
- Operate without trusting any single node or coordinator

Signature validation is handled automatically by the integrated verifier at insertion and retrieval time.

-----

## Network Layer & Application-Level Fragmentation

Since Post-Quantum Cryptography (PQC) records—containing Dilithium signatures and Kyber keys—often exceed the standard UDP MTU, **AuthKademlia-RS** implements a custom application-level fragmentation and reassembly system.

This ensures that messages remain within safe network limits, avoiding unreliable IP-level fragmentation and improving delivery rates across different network topologies.

### The Message Pipeline

When a node publishes or retrieves a record, the data passes through a structured lifecycle:

1.  **Serialize**: The record is serialized using `bincode` for high-performance binary encoding.
2.  **Split**: The payload is divided into **5 chunks**, each prefixed with a specialized **`KADF`** header.
3.  **Send**: The 5 fragments are transmitted independently from sender to receiver.
4.  **Recv**: The receiver populates a `ReassemblyMap`; internal "slots" for the message light up as fragments arrive.
5.  **Assemble**: Once all fragments are received, they are concatenated in the correct order.
6.  **Dispatch**: The reassembled message triggers `rpc_store()`, followed by cryptographic signature verification.
7.  **Response**: A `StoreResult` is sent back to the sender to acknowledge the completed operation.

### Wire Format & Deep Inspection

Each fragment on the wire follows a strict binary layout, allowing for granular monitoring and debugging:

**Fragment Structure (`KADF`):**
`[Header: 4B (KADF)] | [Fragment ID: 16B] | [Index: 1B] | [Total: 1B] | [Payload: Var]`

By inspecting fragments in the queue, you can analyze the internal composition of the PQC record:
* **Dilithium-2 Signature**: Typically spans the first 2-3 chunks due to the size of post-quantum signatures.
* **Kyber Keys & DID Document**: Contained within the remaining chunks.

This system provides real-time visibility into the network state, where the `ReassemblyMap` visually tracks the progress of every incoming high-capacity RPC call.

-----

## DID:IIoT Integration

This implementation is designed to interoperate with the [`did:iiot` method](https://github.com/fratrung/did-iiot), an open DID method targeting **Industrial IoT** environments.

DID Documents stored in the DHT embed **post-quantum public keys** (Dilithium for authentication, Kyber for key exchange), enabling:

- Secure device authentication
- Post-quantum key exchange
- Verifiable credential issuance and resolution

A complete end-to-end integration example is available at [fratrung/did-iiot-dht](https://github.com/fratrung/did-iiot-dht).

-----

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
authkademlia-rs = { git = "https://github.com/fratrung/auth_kademlia" }
```

-----

## Example

```rust
use std::sync::Arc;
use std::path::PathBuf;

use auth_kademlia::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia::network::Server;


use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::{PublicKey, DetachedSignature};
use pqcrypto_traits::kem::{PublicKey as KemPublicKey};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

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

// Helper function to initialize and start a Kademlia node
async fn start_node(port: u16) -> Server {
    // Initialize the signature handler with the issuer's public key
    let handler = Arc::new(DIDSignatureVerifierHandler::new(PathBuf::from("issuer.bin")));
        
    // Create a new Server: ksize=20, alpha=3
    let mut server = Server::new(handler, 20, 3, None, None);
        
    // Start listening on the specified port
    server.listen(port, "127.0.0.1").await.unwrap();
    println!(">>> Node started on port {}", port);
    server
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    
    // Start two local nodes
    let node_1 = start_node(5678).await;
    let node_2 = start_node(5679).await;

    // Node 2 performs bootstrap toward Node 1 to join the network
    println!(">>> Node 2: Performing bootstrap towards Node 1 (5678)...");
    let discovered = node_2.bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;
    
    println!(">>> Node 2 discovered {} nodes during bootstrap", discovered.len());
    
    // Fallback logic if initial bootstrap fails
    if discovered.is_empty() {
        println!(">>> WARNING: Bootstrap failed, forcing manual retry...");
        node_2.bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;
    }
    
    // Allow some time for the DHT routing tables to update
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    node_2.bootstrap(vec![("127.0.0.1".to_string(), 5678)]).await;
    
    sleep(Duration::from_secs(1)).await;

    // --- Post-Quantum Cryptography Section ---
    // Generate PQC keypairs (Dilithium for signatures, Kyber for encryption)
    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let (kyber_pk, _) = kyber512::keypair();
    
    // Create a unique Decentralized Identifier (DID)
    let did = generate_did_iiot();
    let did_doc = build_did_document(&did, &dilithium_pk, &kyber_pk);
    
    // Extract the hash-part of the DID to use as the DHT key
    let dht_key = did.split(':').last().unwrap().to_string();

    // Sign the DID Document using Dilithium-2
    let signed_record = build_signed_record(&did_doc, &dilithium_sk, "Dilithium-2");
    
    // Retry loop to publish the record (waiting for network stabilization)
    let mut is_ready = false;
    for i in 0..10 {
        let success = node_2.set(&dht_key.clone(), signed_record.clone()).await;
        
        if success == Some(true) {
            println!(">>> Network stabilized and record published on attempt {}!", i + 1);
            is_ready = true;
            break;
        }
        println!(">>> Attempt {}: Waiting for neighbors in the DHT...", i + 1);
        sleep(Duration::from_millis(500)).await;
    }

    if !is_ready {
        println!(">>> ERROR: Failed to publish the record to the DHT.");
        return Ok(());
    }

    println!(">>> Node 1: Retrieving record '{}'...", dht_key);
    match node_1.get(&dht_key).await {
        Some(record) => {
            println!(">>> Node 1: Record found! ({} bytes)", record.len());
            
            // Parse the binary record: [Algorithm Name (12 bytes)] [Signature] [DID Document JSON]
            let alg_cow = String::from_utf8_lossy(&record[0..12]);
            let alg = alg_cow.trim_matches(char::from(0)); // Remove null padding
            let doc_start = 12 + dilithium2::signature_bytes();
            let doc_bytes = &record[doc_start..];
            
            if let Ok(doc) = serde_json::from_slice::<Value>(doc_bytes) {
                println!(">>> Analysis:");
                println!("    - Algorithm: {}", alg);
                println!("    - DID Document ID: {}", doc["id"]);
                println!("    - Full JSON: {}", serde_json::to_string_pretty(&doc).unwrap());
            }
        },
        None => println!(">>> Node 1: Record not found!"),
    }

    Ok(())
}

```

## Logging

AuthKademlia-RS uses the [`tracing`](https://docs.rs/tracing) ecosystem for structured, level-based logging. To enable debug output:

```rust
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::DEBUG)
    .init();
```

-----

## Related Projects

- [AuthKademlia](https://github.com/fratrung/AuthKademlia) — original Python implementation
- [did:iiot](https://github.com/fratrung/did-iiot) — DID method for Industrial IoT
- [did-iiot-dht](https://github.com/fratrung/did-iiot-dht) — end-to-end integration example