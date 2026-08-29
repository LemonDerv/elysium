use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tracing::{debug, info, trace, warn};

/// Result of decapsulating a packet
#[derive(Debug)]
pub enum DecapsulateOutput {
    /// Plaintext IP packet to be injected into the TUN virtual adapter
    TunnelPacket(Vec<u8>),
    /// Handshake or keepalive packet to be sent to peer over UDP
    NetworkPacket(Vec<u8>),
    /// Decapsulation succeeded with no output required
    Done,
}

/// Manages WireGuard tunnels for peers
pub struct WireGuardManager {
    tunnels: HashMap<Ipv4Addr, Box<Tunn>>,
    network: u32,
    netmask: u32,
}

impl WireGuardManager {
    /// Create a new WireGuardManager
    pub fn new(subnet: &str) -> Result<Self> {
        let (network, netmask) = Self::parse_cidr(subnet)?;
        Ok(Self {
            tunnels: HashMap::new(),
            network,
            netmask,
        })
    }

    fn parse_cidr(cidr: &str) -> Result<(u32, u32)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid CIDR format"));
        }
        let ip: Ipv4Addr = parts[0].parse()?;
        let prefix: u32 = parts[1].parse()?;
        if prefix > 32 {
            return Err(anyhow!("Invalid CIDR prefix"));
        }
        let mask = if prefix == 0 { 0 } else { (!0u32) << (32 - prefix) };
        let network = u32::from_be_bytes(ip.octets()) & mask;
        Ok((network, mask))
    }

    /// Creates a Tunn for a peer
    pub fn create_tunnel(
        &mut self,
        own_private_key: &StaticSecret,
        peer_public_key: &PublicKey,
        peer_ip: Ipv4Addr,
    ) -> Result<()> {
        info!("Creating tunnel for peer: {}", peer_ip);
        let tunn = Tunn::new(
            own_private_key.clone(),
            *peer_public_key,
            None,
            Some(25), // 25 second keepalive
            0,
            None,
        );
        
        self.tunnels.insert(peer_ip, Box::new(tunn));
        Ok(())
    }

    /// Encrypt an outgoing IP packet, returns WireGuard UDP payload
    pub fn encrypt_packet(&mut self, peer_ip: Ipv4Addr, packet: &[u8]) -> Result<Vec<u8>> {
        // Validate destination IP if packet contains an IPv4 header
        if packet.len() >= 20 {
            let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            if dst_ip != peer_ip && !dst_ip.is_broadcast() && dst_ip != Ipv4Addr::new(10, 7, 0, 255) {
                warn!("Outgoing packet destination {} does not match peer tunnel IP {}", dst_ip, peer_ip);
            }
        }

        let tunn = self.tunnels.get_mut(&peer_ip)
            .ok_or_else(|| anyhow!("Tunnel not found for peer {}", peer_ip))?;
            
        let mut buf = vec![0u8; packet.len() + 32 + 16]; // Padding for WG header and MACs
        match tunn.encapsulate(packet, &mut buf) {
            TunnResult::WriteToNetwork(packet_out) => {
                Ok(packet_out.to_vec())
            }
            TunnResult::Err(e) => Err(anyhow!("Encapsulation error: {:?}", e)),
            _ => Err(anyhow!("Failed to encapsulate packet")),
        }
    }

    /// Decrypt incoming WireGuard UDP data with strict Cryptokey Routing (AllowedIPs) verification
    pub fn decrypt_packet(&mut self, peer_ip: Ipv4Addr, data: &[u8]) -> Result<DecapsulateOutput> {
        let tunn = self.tunnels.get_mut(&peer_ip)
            .ok_or_else(|| anyhow!("Tunnel not found for peer {}", peer_ip))?;
            
        let mut buf = vec![0u8; data.len() + 64];
        match tunn.decapsulate(None, data, &mut buf) {
            TunnResult::WriteToNetwork(packet_out) => {
                debug!("WG decapsulate produced network handshake response for {}", peer_ip);
                Ok(DecapsulateOutput::NetworkPacket(packet_out.to_vec())) 
            }
            TunnResult::WriteToTunnelV4(packet_out, _) => {
                // Cryptokey Routing enforcement: Verify source IPv4 address
                if packet_out.len() >= 20 {
                    let src_ip = Ipv4Addr::new(packet_out[12], packet_out[13], packet_out[14], packet_out[15]);
                    if src_ip != peer_ip {
                        warn!("Cryptokey routing violation: dropped spoofed packet with claimed src {} from peer {}", src_ip, peer_ip);
                        return Ok(DecapsulateOutput::Done);
                    }
                    
                    // Anti-Lateral Movement: Verify destination IPv4 address is within virtual subnet
                    let dst_ip_bytes = [packet_out[16], packet_out[17], packet_out[18], packet_out[19]];
                    let dst_ip_u32 = u32::from_be_bytes(dst_ip_bytes);
                    if (dst_ip_u32 & self.netmask) != self.network {
                        let dst_ip = Ipv4Addr::from(dst_ip_bytes);
                        warn!("Lateral movement blocked: dropped packet destined for external network {} from peer {}", dst_ip, peer_ip);
                        return Ok(DecapsulateOutput::Done);
                    }
                }
                Ok(DecapsulateOutput::TunnelPacket(packet_out.to_vec()))
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                warn!("Dropped IPv6 packet: only IPv4 is supported in this virtual LAN");
                Ok(DecapsulateOutput::Done)
            }
            TunnResult::Done => Ok(DecapsulateOutput::Done),
            TunnResult::Err(e) => Err(anyhow!("Decapsulation error: {:?}", e)),
        }
    }

    /// Called periodically to handle WireGuard timers
    pub fn handle_timer(&mut self) -> Vec<(Ipv4Addr, Vec<u8>)> {
        let mut timer_packets = Vec::new();
        for (ip, tunn) in self.tunnels.iter_mut() {
            let mut buf = vec![0u8; 1024];
            match tunn.update_timers(&mut buf) {
                TunnResult::WriteToNetwork(packet_out) => {
                    trace!("Timer triggered network write for {}", ip);
                    timer_packets.push((*ip, packet_out.to_vec()));
                }
                _ => {}
            }
        }
        timer_packets
    }
}
