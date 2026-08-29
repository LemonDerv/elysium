use anyhow::Result;
use iroh::endpoint::Connection;
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use tracing::info;

use crate::network::peer::PeerManager;

/// WireGuard keys and network info to exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerExchangeInfo {
    pub wg_public_key: String,
    pub virtual_ip: Ipv4Addr,
    pub udp_endpoints: Vec<SocketAddr>,
    pub node_name: String,
}

/// Service for room discovery and signaling
pub struct DiscoveryService;

impl DiscoveryService {
    /// Make room discoverable
    pub async fn publish_room(room_code: &str, endpoint_addr: EndpointAddr) -> Result<()> {
        info!("Publishing room: {} with EndpointAddr: {:?}", room_code, endpoint_addr);
        // Placeholder for publishing to discovery network
        Ok(())
    }

    /// Look up a room by code
    pub async fn find_room(room_code: &str) -> Result<EndpointAddr> {
        info!("Finding room by code: {}", room_code);
        Err(anyhow::anyhow!("Room lookup not implemented yet"))
    }

    /// Exchange WireGuard public keys, virtual IPs, etc., over the iroh connection
    pub async fn exchange_peer_info(conn: &Connection, our_info: PeerExchangeInfo) -> Result<PeerExchangeInfo> {
        info!("Exchanging peer info...");
        
        let msg = serde_json::to_vec(&our_info)?;
        PeerManager::send_message(conn, &msg).await?;
        
        // Early Rejection: Limit incoming JSON size to 4KB to prevent OOM
        let recv = PeerManager::recv_message(conn, 4096).await?;
        let peer_info: PeerExchangeInfo = serde_json::from_slice(&recv)?;
        
        // Ensure string limits are respected even within the 4KB boundary
        if peer_info.node_name.len() > 64 {
            anyhow::bail!("Peer provided an excessively long node name");
        }
        
        Ok(peer_info)
    }
}
