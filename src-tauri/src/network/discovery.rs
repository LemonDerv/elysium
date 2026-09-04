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

/// Dynamic control messages exchanged over QUIC streams
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ControlMessage {
    PeerInfo(PeerExchangeInfo),
    PeerInfoResponse(PeerExchangeInfo),
    RosterUpdate { peers: Vec<crate::room::PeerInfo> },
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

    /// As a client, send our info and wait for host response
    pub async fn exchange_peer_info_client(conn: &Connection, our_info: PeerExchangeInfo) -> Result<PeerExchangeInfo> {
        info!("Sending peer info to host...");
        
        let msg = serde_json::to_vec(&our_info)?;
        PeerManager::send_message(conn, &msg).await?;
        
        // Wait for response from host
        let recv = PeerManager::recv_message(conn, 4096).await?;
        let peer_info: PeerExchangeInfo = serde_json::from_slice(&recv)?;
        
        if peer_info.node_name.len() > 64 {
            anyhow::bail!("Host provided an excessively long node name");
        }
        Ok(peer_info)
    }

    /// As a host, wait for client info
    pub async fn exchange_peer_info_host(conn: &Connection) -> Result<PeerExchangeInfo> {
        info!("Waiting for peer info from client...");
        let recv = PeerManager::recv_message(conn, 4096).await?;
        let peer_info: PeerExchangeInfo = serde_json::from_slice(&recv)?;
        
        if peer_info.node_name.len() > 64 {
            anyhow::bail!("Client provided an excessively long node name");
        }
        Ok(peer_info)
    }

    /// As a host, send our response back to client
    pub async fn send_peer_info_response(conn: &Connection, our_info: PeerExchangeInfo) -> Result<()> {
        let msg = serde_json::to_vec(&our_info)?;
        PeerManager::send_message(conn, &msg).await?;
        Ok(())
    }

    /// Broadcast or send updated room roster to a peer
    pub async fn send_roster_update(conn: &Connection, peers: &[crate::room::PeerInfo]) -> Result<()> {
        let msg = ControlMessage::RosterUpdate {
            peers: peers.to_vec(),
        };
        let bytes = serde_json::to_vec(&msg)?;
        PeerManager::send_message(conn, &bytes).await?;
        Ok(())
    }
}
