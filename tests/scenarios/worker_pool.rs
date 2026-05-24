//! Scenario: worker pool no-drop under burst.
//!
//! Fires N concurrent bootstrap calls at a single target node, all at the same
//! instant. Each bootstrap sends at least one FIND_NODE RPC. The worker pool
//! must process all of them and return a response — zero drops.
//!
//! The worker pool uses round-robin dispatch with per-worker channels of depth
//! 256. With N=40 concurrent clients, the total burst fits well within capacity.
//! This establishes a no-regression baseline for the new pool implementation.
//!
//! Ports: target=15800, clients=15801–15840.

#[path = "common.rs"]
mod common;

use common::{rt, start_node};

const TARGET_PORT: u16 = 15800;
const N_CLIENTS: usize = 40;

#[test]
fn worker_pool_delivers_all_responses_under_burst() {
    rt().block_on(async {
        let _target = start_node(TARGET_PORT).await;

        let mut clients = Vec::with_capacity(N_CLIENTS);
        for i in 0..N_CLIENTS {
            clients.push(start_node(TARGET_PORT + 1 + i as u16).await);
        }

        // Fire all bootstrap calls concurrently — burst of N RPCs to target.
        let results = futures::future::join_all(
            clients
                .iter()
                .map(|c| c.bootstrap(vec![("127.0.0.1".to_string(), TARGET_PORT)])),
        )
        .await;

        let successful = results.iter().filter(|r| !r.is_empty()).count();
        assert_eq!(
            successful, N_CLIENTS,
            "{}/{} bootstrap calls received a response — worker pool must not drop any",
            successful, N_CLIENTS
        );
    });
}
