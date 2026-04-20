use std::path::PathBuf;
use std::sync::Arc;

use auth_kademlia::auth_handler::DIDSignatureVerifierHandler;
use auth_kademlia::network::Server;

#[tokio::main]
async fn main() {

    let issuer_key_path = PathBuf::from("issuer_node_public_key.txt");
    let handler = Arc::new(DIDSignatureVerifierHandler::new(issuer_key_path));

    let mut server = Server::new(
        handler,
        25,   // ksize
        5,    // alpha
        None, // node_id random
        None, // storage default
    );

    server.listen(8468, "0.0.0.0").await.expect("Failed to bind");

    // Bootstrap verso nodi noti
    // server.bootstrap(vec![("192.168.1.10".to_string(), 8468)]).await;

    println!("AuthKademlia node running. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await.unwrap();
    server.stop().await;
}
