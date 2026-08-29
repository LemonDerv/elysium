use anyhow::{anyhow, Result};
use rand::Rng;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tracing::{info, warn};

/// Nat types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    FullCone,
    Restricted,
    Symmetric,
}

/// NAT information result
#[derive(Debug, Clone)]
pub struct NatInfo {
    pub local_addrs: Vec<Ipv4Addr>,
    pub external_addr: Option<SocketAddr>,
    pub nat_type: NatType,
}

/// Simple NAT traversal utility
pub struct NatTraversal;

impl NatTraversal {
    /// Discover public IP using a STUN server (stun.l.google.com:19302)
    pub fn discover_external_addr() -> Result<SocketAddr> {
        info!("Discovering external address via STUN...");
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(2)))?;
        socket.connect("stun.l.google.com:19302")?;

        // Simple STUN binding request
        let mut req = [0u8; 20];
        req[0] = 0x00;
        req[1] = 0x01; // Binding Request
        // Length (0)
        req[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes()); // Magic cookie
        // Transaction ID (12 bytes)
        rand::rng().fill(&mut req[8..20]);

        socket.send(&req)?;

        let mut buf = [0u8; 1024];
        let n = socket.recv(&mut buf)?;

        // Parse STUN response (basic XOR-MAPPED-ADDRESS parsing) and validate transaction ID
        if n >= 20 && buf[0] == 0x01 && buf[1] == 0x01 && buf[8..20] == req[8..20] {
            let mut offset = 20;
            while offset + 4 <= n {
                let attr_type = u16::from_be_bytes([buf[offset], buf[offset+1]]);
                let attr_len = u16::from_be_bytes([buf[offset+2], buf[offset+3]]) as usize;
                
                if attr_type == 0x0020 && attr_len >= 8 && offset + 4 + attr_len <= n { // XOR-MAPPED-ADDRESS
                    let family = buf[offset+5];
                    if family == 0x01 { // IPv4
                        let port = u16::from_be_bytes([buf[offset+6], buf[offset+7]]) ^ 0x2112;
                        let mut ip = [0u8; 4];
                        ip.copy_from_slice(&buf[offset+8..offset+12]);
                        let ip = u32::from_be_bytes(ip) ^ 0x2112A442;
                        let addr = SocketAddr::new(Ipv4Addr::from(ip).into(), port);
                        info!("Discovered external address: {}", addr);
                        return Ok(addr);
                    }
                }
                offset += 4 + attr_len;
            }
        }
        
        Err(anyhow!("Failed to parse STUN response"))
    }

    /// Placeholder that tries UPnP mapping
    pub fn attempt_upnp_mapping(internal_port: u16) -> Option<(Ipv4Addr, u16)> {
        warn!("UPnP mapping attempt not fully implemented yet for port {}", internal_port);
        // TODO: implement with igd-next
        None
    }

    /// Lists local network interface IPs
    pub fn get_local_addrs() -> Vec<Ipv4Addr> {
        // Stub implementation, would use a crate like local-ip-address or if_addrs
        vec![Ipv4Addr::new(127, 0, 0, 1)]
    }

    /// Get all NAT info
    pub fn get_nat_info(_port: u16) -> NatInfo {
        let external = Self::discover_external_addr().ok();
        // If we want UPnP
        // Self::attempt_upnp_mapping(port);
        
        NatInfo {
            local_addrs: Self::get_local_addrs(),
            external_addr: external,
            nat_type: NatType::Unknown,
        }
    }
}
