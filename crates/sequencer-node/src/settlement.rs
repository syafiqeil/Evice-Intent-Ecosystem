// crates/sequencer-node/src/settlement.rs

use aegis_node::rpc_client::Client as AegisClient;
use std::net::SocketAddr;
use tarpc::{Client, context};
use tokio::net::TcpStream;
use tracing::{info, error};

pub struct SettlementEngine {
    client: Option<AegisClient>,
}

impl SettlementEngine {
    pub async fn new(aegis_addr: String) -> Self {
        info!("Connecting to Aegis Settlement Layer at {}...", aegis_addr);

        let client = match TcpStream::connect(&aegis_addr).await {
            Ok(stream) => {
                let transport = tarpc::serde_transport::Transport::new(
                    tarpc::serde_transport::new(stream, tarpc::tokio_serde::formats::Json::default()),
                    tarpc::tokio_serde::formats::Json::default()
                );
                let client = AegisClient::new(client::Config::default(), transport).spawn();
                info!("✅ Connected to Aegis L1!");
                Some(client)
            }
            Err(e) => {
                error!("⚠️ Failed to connect to Aegis: {}. Settlement disabled.", e);
                None
            }
        };

        Self { client }
    }

    pub async fn submit_batch(&self, batch_data: Vec<u8>) {
        if let Some(client) = &self.client {
            info!("Submitting Batch to Aegis (Size: {} bytes)...", batch_data.len());

            // CONTOH CALL (Sesuaikan dengan definisi RPC Aegis Anda):
            // let context = context::current();
            // match client.submit_transaction(context, batch_data).await {
            //     Ok(tx_hash) => info!("✅ Batch Finalized! Hash: {:?}", tx_hash),
            //     Err(e) => error!("❌ Settlement Failed: {:?}", e),
            // }
            
            // Mock Log dulu agar compile
            info!("(Mock) Batch submitted successfully.");
        } else {
            error!("❌ Cannot submit batch: Aegis not connected.");
        }
    }
}