//! Full DHT integration tests — multi-node flows.
//!
//! Context: these tests exercise the complete application stack: UDP sockets,
//! the Kademlia protocol layer, routing-table updates, and cryptographic record
//! verification.  Each test spins up real DHT nodes on loopback and validates
//! the end-to-end behaviour described in the README.
//!
//! Covered flows:
//!   1. Two-node bootstrap — nodes discover each other.
//!   2. Cross-node publish & retrieve — Node A stores, Node B retrieves.
//!   3. Duplicate-key rejection — `set` on an existing key returns None.
//!   4. Key-rotation update — a DID owner rotates their key (update flow).
//!   5. Authenticated delete — a DID owner deletes their record.
//!   6. Invalid-signature rejection — malformed records are refused on `set`.
//!   7. Bootstrap with no reachable peers — returns empty list gracefully.
//!
//! Port allocation (each test uses a dedicated range to allow parallel execution):
//!   - test 1: 15700–15701
//!   - test 2: 15710–15711
//!   - test 3: 15720–15721
//!   - test 4: 15730–15732
//!   - test 5: 15740–15741
//!   - test 6: 15750
//!   - test 7: 15760

mod common;

use pqcrypto_dilithium::dilithium2;
use pqcrypto_kyber::kyber512;
use pqcrypto_traits::sign::DetachedSignature;
use tokio::time::{sleep, Duration};

use common::{build_did_document, build_signed_record, generate_did_iiot, start_node};

// ─────────────────────────────────────────────────────────────────────────────
// 1. Two-node bootstrap
// ─────────────────────────────────────────────────────────────────────────────

/// Two nodes bootstrap from each other and end up in each other's routing table.
#[tokio::test]
async fn test_two_node_bootstrap_discover_each_other() {
    let _node1 = start_node(15700).await;
    let node2 = start_node(15701).await;

    let discovered = node2.bootstrap(vec![("127.0.0.1".to_string(), 15700)]).await;

    // After bootstrap, node2 should have discovered node1 (and possibly itself).
    assert!(
        !discovered.is_empty(),
        "bootstrap should discover at least the seed node"
    );

    // node2 should now have node1 as a bootstrappable neighbour.
    let neighbours = node2.bootstrappable_neighbors().await;
    assert!(
        !neighbours.is_empty(),
        "after bootstrap, routing table should contain at least one neighbour"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Cross-node publish & retrieve
// ─────────────────────────────────────────────────────────────────────────────

/// Node A stores a signed DID record; Node B retrieves it.
/// This is the primary use case described in the README.
#[tokio::test]
async fn test_set_on_node_a_and_get_from_node_b() {
    let mut node_a = start_node(15710).await;
    let node_b = start_node(15711).await;

    // Bootstrap so both nodes are aware of each other.
    node_b.bootstrap(vec![("127.0.0.1".to_string(), 15710)]).await;
    sleep(Duration::from_millis(200)).await;

    // Build a valid signed DID record.
    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let doc = build_did_document(&did, &dpk, &kpk);
    let key = did.split(':').last().unwrap().to_string();
    let record = build_signed_record(&doc, &dsk, "Dilithium-2");

    // Node A publishes the record.
    let store_result = node_a.set(&key, record.clone()).await;
    assert!(
        store_result.unwrap_or(false),
        "set should succeed on the first call"
    );

    // Node B retrieves it — may come from node_a via the network.
    let retrieved = node_b.get(&key).await;
    assert!(retrieved.is_some(), "Node B should be able to retrieve the record stored by Node A");

    // Verify the retrieved bytes match what was stored.
    assert_eq!(retrieved.unwrap(), record);

    node_a.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Duplicate-key rejection
// ─────────────────────────────────────────────────────────────────────────────

/// `set` on a key that already exists returns `None` (immutable records).
#[tokio::test]
async fn test_set_duplicate_key_rejected() {
    let mut node = start_node(15720).await;
    let node_b = start_node(15721).await;
    node_b.bootstrap(vec![("127.0.0.1".to_string(), 15720)]).await;
    sleep(Duration::from_millis(200)).await;

    let (dpk, dsk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let doc = build_did_document(&did, &dpk, &kpk);
    let key = did.split(':').last().unwrap().to_string();
    let record = build_signed_record(&doc, &dsk, "Dilithium-2");

    // First set must succeed.
    let first = node.set(&key, record.clone()).await;
    assert!(first.unwrap_or(false), "first set must succeed");

    // Second set on the same key must be rejected.
    let second = node.set(&key, record.clone()).await;
    assert!(
        second.is_none(),
        "duplicate set must return None — records are immutable"
    );

    node.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Key-rotation update
// ─────────────────────────────────────────────────────────────────────────────

/// A DID owner rotates their key using the `update` operation:
///   1. Store old record (signed with old keypair).
///   2. Build new record (signed with new keypair).
///   3. auth_sig = Sign(new_record_bytes, old_secret_key) — proves ownership.
///   4. `update` succeeds; subsequent `get` returns the new record.
#[tokio::test]
async fn test_update_did_record_key_rotation() {
    let mut node1 = start_node(15730).await;
    let node2 = start_node(15731).await;
    let node3 = start_node(15732).await;

    node2.bootstrap(vec![("127.0.0.1".to_string(), 15730)]).await;
    node3.bootstrap(vec![("127.0.0.1".to_string(), 15730)]).await;
    sleep(Duration::from_millis(300)).await;

    // ── Step 1: generate old keypair and publish original record ──────────────
    let (old_pk, old_sk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').last().unwrap().to_string();
    let old_doc = build_did_document(&did, &old_pk, &kpk);
    let old_record = build_signed_record(&old_doc, &old_sk, "Dilithium-2");

    let stored = node2.set(&key, old_record.clone()).await;
    assert!(stored.unwrap_or(false), "initial store must succeed");

    // ── Step 2: generate new keypair and build new record ─────────────────────
    let (new_pk, new_sk) = dilithium2::keypair();
    let (new_kpk, _) = kyber512::keypair();
    let new_doc = build_did_document(&did, &new_pk, &new_kpk);
    let new_record = build_signed_record(&new_doc, &new_sk, "Dilithium-2");

    // ── Step 3: auth_sig proves old owner authorises this rotation ────────────
    // The protocol verifies: old_pub_key.verify(new_record, auth_sig)
    let auth_sig_ds = dilithium2::detached_sign(&new_record, &old_sk);
    let auth_sig = auth_sig_ds.as_bytes().to_vec();

    // ── Step 4: update via node3 ──────────────────────────────────────────────
    let updated = node3.update(&key, new_record.clone(), Some(auth_sig)).await;
    assert!(
        updated.unwrap_or(false),
        "key-rotation update must succeed"
    );

    // ── Step 5: subsequent get should return the NEW record ───────────────────
    // Give the network a moment to propagate the update.
    sleep(Duration::from_millis(300)).await;
    let retrieved = node1.get(&key).await;
    assert!(retrieved.is_some(), "get after update must return the new record");
    assert_eq!(
        retrieved.unwrap(),
        new_record,
        "retrieved record must match the updated record"
    );

    node1.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Authenticated delete
// ─────────────────────────────────────────────────────────────────────────────

/// A DID owner deletes their record by signing a delete message with their key.
/// After deletion, `get` returns None.
#[tokio::test]
async fn test_delete_did_record() {
    let mut node1 = start_node(15740).await;
    let node2 = start_node(15741).await;

    node2.bootstrap(vec![("127.0.0.1".to_string(), 15740)]).await;
    sleep(Duration::from_millis(500)).await;

    // Store a record.
    let (pk, sk) = dilithium2::keypair();
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').last().unwrap().to_string();
    let doc = build_did_document(&did, &pk, &kpk);
    let record = build_signed_record(&doc, &sk, "Dilithium-2");

    let stored = node1.set(&key, record.clone()).await;
    assert!(stored.unwrap_or(false), "store must succeed before delete test");
    sleep(Duration::from_millis(500)).await;

    // Build and sign the delete message.
    let delete_msg = b"DELETE THIS DID RECORD";
    let del_sig_ds = dilithium2::detached_sign(delete_msg, &sk);
    let del_sig = del_sig_ds.as_bytes().to_vec();

    // Node2 requests the delete.
    let deleted = node2
        .delete(&key, del_sig, delete_msg.to_vec())
        .await;
    assert!(
        deleted.unwrap_or(false),
        "authenticated delete must succeed"
    );

    // After deletion, get should return None.
    sleep(Duration::from_millis(500)).await;
    let after = node1.get(&key).await;
    assert!(
        after.is_none(),
        "get after authenticated delete must return None"
    );

    node1.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Invalid-signature rejection
// ─────────────────────────────────────────────────────────────────────────────

/// A record whose embedded signature does not match the public key in the
/// DID Document must be rejected by `set` (returns None).
#[tokio::test]
async fn test_invalid_signature_record_rejected_on_set() {
    let mut node = start_node(15750).await;

    let (pk, _correct_sk) = dilithium2::keypair();
    let (_, wrong_sk) = dilithium2::keypair(); // different secret key — mismatch!
    let (kpk, _) = kyber512::keypair();
    let did = generate_did_iiot();
    let key = did.split(':').last().unwrap().to_string();

    // Build a record: DID Doc embeds `pk` (key A's public key) but the
    // signature is produced with `wrong_sk` (key B's secret key).
    let doc = build_did_document(&did, &pk, &kpk);
    let invalid_record = build_signed_record(&doc, &wrong_sk, "Dilithium-2");

    let result = node.set(&key, invalid_record).await;
    assert!(
        result.is_none(),
        "set with mismatched signature must return None"
    );

    node.stop().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Bootstrap with no reachable peers
// ─────────────────────────────────────────────────────────────────────────────

/// Bootstrapping against an address where no node is listening returns an
/// empty discovered list gracefully (no panic, no hang).
#[tokio::test]
async fn test_bootstrap_unreachable_peer_returns_empty() {
    let node = start_node(15760).await;

    // Port 15799 has no listener.
    let discovered = node
        .bootstrap(vec![("127.0.0.1".to_string(), 15799)])
        .await;

    assert!(
        discovered.is_empty(),
        "bootstrap against an unreachable peer must return an empty list"
    );
}
