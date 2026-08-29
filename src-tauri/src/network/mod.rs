use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info};

pub mod discovery;
pub mod nat;
pub mod peer;
pub mod tunnel;
pub mod wireguard;

use crate::network::peer::PeerManager;
use crate::network::tunnel::TunnelManager;
use crate::network::wireguard::WireGuardManager;

/// Main network engine orchestrating the virtual LAN
pub struct NetworkEngine {
    tunnel_manager: Arc<Mutex<TunnelManager>>,
    wg_manager: Arc<RwLock<WireGuardManager>>,
    peer_manager: Arc<PeerManager>,
    packet_tx: mpsc::Sender<Vec<u8>>,
    packet_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
}

impl NetworkEngine {
    /// Create a new NetworkEngine instance
    pub fn new(
        tunnel_manager: TunnelManager,
        wg_manager: WireGuardManager,
        peer_manager: PeerManager,
    ) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        
        Self {
            tunnel_manager: Arc::new(Mutex::new(tunnel_manager)),
            wg_manager: Arc::new(RwLock::new(wg_manager)),
            peer_manager: Arc::new(peer_manager),
            packet_tx: tx,
            packet_rx: Arc::new(Mutex::new(rx)),
        }
    }

    /// Start the network engine packet loop
    pub async fn start(&self) -> Result<()> {
        info!("Starting NetworkEngine");
        
        // Start tunnel reading task
        let mut tm = self.tunnel_manager.lock().await;
        tm.start_reading(self.packet_tx.clone()).await?;

        // Packet forwarding loop placeholder
        // Normally you would spawn a task to process packet_rx
        let rx = self.packet_rx.clone();
        tokio::spawn(async move {
            let mut rx = rx.lock().await;
            while let Some(packet) = rx.recv().await {
                debug!("Received packet of size: {}", packet.len());
                // TODO: Read IP header, find dest IP, pass to WireGuardManager to encrypt,
                // then send out via UDP to the correct peer.
            }
        });

        Ok(())
    }

    /// Stop the network engine
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping NetworkEngine");
        let mut tm = self.tunnel_manager.lock().await;
        tm.shutdown()?;
        Ok(())
    }
}
