use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_std, Engine};
use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use tracing::info;

/// Information about a peer connected to the room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// The public key of the peer (base64 encoded).
    pub public_key: String,
    /// The virtual IP address assigned to the peer within the LAN.
    pub virtual_ip: Ipv4Addr,
    /// The node name of the peer.
    pub node_name: String,
    /// Latency in milliseconds to this peer.
    pub latency_ms: Option<f64>,
    /// Jitter in milliseconds to this peer (RFC 3550 IPDV).
    #[serde(default)]
    pub jitter_ms: Option<f64>,
    /// Packet loss percentage (0.0 - 100.0) to this peer.
    #[serde(default)]
    pub packet_loss_pct: Option<f64>,
    /// Whether the peer is currently considered connected.
    pub connected: bool,
}

/// Represents an Elysium virtual LAN room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    /// The unique room code.
    pub room_code: String,
    /// The public key of the host (base64 encoded).
    pub host_public_key: String,
    /// List of peers in the room (includes the host).
    pub peers: Vec<PeerInfo>,
    /// The virtual subnet for this room, e.g., "10.7.0.0/24".
    pub subnet: String,
    /// Unix timestamp of when the room was created.
    pub created_at: i64,
}

impl Room {
    const CODE_CHARSET: &'static [u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Removed ambiguous 0/O, 1/I

    /// Validate room code format (base64 JSON of EndpointAddr)
    pub fn validate_room_code(code: &str) -> Result<()> {
        let decoded = base64_std.decode(code.trim())
            .map_err(|_| anyhow!("Invalid room code format (not base64)"))?;
        serde_json::from_slice::<iroh::EndpointAddr>(&decoded)
            .map_err(|_| anyhow!("Invalid room code format (not EndpointAddr)"))?;
        Ok(())
    }

    /// Generate a room code from the host's EndpointAddr
    pub fn generate_room_code(addr: &iroh::EndpointAddr) -> Result<String> {
        let json = serde_json::to_string(addr)?;
        Ok(base64_std.encode(json.as_bytes()))
    }

    /// Create a new room with the given host.
    pub fn create_room(host_public_key: String, host_node_name: String, addr: &iroh::EndpointAddr) -> Result<Self> {
        if host_node_name.len() > 64 {
            anyhow::bail!("Host node name exceeds maximum allowed length of 64 characters");
        }
        let room_code = Self::generate_room_code(addr)?;
        let host_ip = Ipv4Addr::new(10, 7, 0, 1);
        
        let host_peer = PeerInfo {
            public_key: host_public_key.clone(),
            virtual_ip: host_ip,
            node_name: host_node_name,
            latency_ms: Some(0.0),
            jitter_ms: Some(0.0),
            packet_loss_pct: Some(0.0),
            connected: true,
        };

        Ok(Self {
            room_code,
            host_public_key,
            peers: vec![host_peer],
            subnet: "10.7.0.0/24".to_string(),
            created_at: Utc::now().timestamp(),
        })
    }

    /// Allocate the next available IP address in the 10.7.0.0/24 subnet.
    pub fn allocate_ip(&self) -> Result<Ipv4Addr> {
        let mut used_ips: Vec<u8> = self.peers.iter().map(|p| p.virtual_ip.octets()[3]).collect();
        used_ips.sort_unstable();

        // 10.7.0.1 is host, so peers start from 2.
        for i in 2..=254 {
            if !used_ips.contains(&i) {
                return Ok(Ipv4Addr::new(10, 7, 0, i));
            }
        }
        anyhow::bail!("No available IP addresses in the subnet")
    }

    /// Join a room as a new peer.
    pub fn join_room(&mut self, public_key: String, node_name: String) -> Result<Ipv4Addr> {
        // Anti-Resource Exhaustion: Reject excessively long node names at the entry point
        if node_name.len() > 64 {
            anyhow::bail!("Node name exceeds maximum allowed length of 64 characters");
        }
        // Validate base64 public key
        let decoded = base64_std.decode(&public_key)
            .context("Invalid base64 public key")?;
        if decoded.len() != 32 {
            anyhow::bail!("Invalid public key length: expected 32 bytes");
        }

        if self.get_peer_by_key(&public_key).is_some() {
            anyhow::bail!("Peer is already in the room");
        }

        let allocated_ip = self.allocate_ip()?;
        let peer = PeerInfo {
            public_key,
            virtual_ip: allocated_ip,
            node_name: node_name.clone(),
            latency_ms: None,
            jitter_ms: None,
            packet_loss_pct: None,
            connected: true,
        };

        self.peers.push(peer);
        info!("Peer {} joined room {} with IP {}", node_name, self.room_code, allocated_ip);
        Ok(allocated_ip)
    }

    /// Remove a peer from the room by their public key.
    pub fn remove_peer(&mut self, public_key: &str) -> Result<()> {
        let len_before = self.peers.len();
        self.peers.retain(|p| p.public_key != public_key);
        if self.peers.len() < len_before {
            info!("Peer {} removed from room", public_key);
            Ok(())
        } else {
            anyhow::bail!("Peer not found in room")
        }
    }

    /// Get a reference to a peer by their virtual IP.
    pub fn get_peer_by_ip(&self, ip: &Ipv4Addr) -> Option<&PeerInfo> {
        self.peers.iter().find(|p| &p.virtual_ip == ip)
    }

    /// Get a reference to a peer by their public key.
    pub fn get_peer_by_key(&self, public_key: &str) -> Option<&PeerInfo> {
        self.peers.iter().find(|p| p.public_key == public_key)
    }
}

/// Manager for handling the currently active room.
#[derive(Debug, Default)]
pub struct RoomManager {
    pub active_room: Option<Room>,
}

impl RoomManager {
    pub fn new() -> Self {
        Self { active_room: None }
    }

    pub fn set_active_room(&mut self, room: Room) {
        self.active_room = Some(room);
    }

    pub fn get_active_room(&self) -> Option<&Room> {
        self.active_room.as_ref()
    }

    pub fn get_active_room_mut(&mut self) -> Option<&mut Room> {
        self.active_room.as_mut()
    }

    pub fn clear_active_room(&mut self) {
        self.active_room = None;
    }
}
