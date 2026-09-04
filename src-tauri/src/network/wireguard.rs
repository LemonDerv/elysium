use anyhow::{anyhow, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
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

/// Token bucket rate limiter for broadcast packets per peer to prevent broadcast storms.
pub struct BroadcastRateLimiter {
    tokens: f64,
    last_update: std::time::Instant,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
}

impl BroadcastRateLimiter {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            last_update: std::time::Instant::now(),
            max_tokens,
            refill_rate,
        }
    }

    /// Attempts to consume one token. Returns true if allowed, false if rate limited.
    pub fn allow(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-peer tunnel state with reusable buffers.
///
/// Each peer gets its own `PeerTunnel` behind an `Arc<Mutex<>>`, so
/// Peer A's crypto work never blocks Peer B.
pub struct PeerTunnel {
    tunn: Box<Tunn>,
    decrypt_buf: Vec<u8>,
    encrypt_buf: Vec<u8>,
    pub is_gateway: bool,
    pub broadcast_limiter: BroadcastRateLimiter,
}

impl PeerTunnel {
    fn new(tunn: Tunn, is_gateway: bool) -> Self {
        Self {
            tunn: Box::new(tunn),
            decrypt_buf: vec![0u8; 65536],
            encrypt_buf: vec![0u8; 2048],
            is_gateway,
            broadcast_limiter: BroadcastRateLimiter::new(150.0, 100.0), // 150 burst, 100 pkt/s
        }
    }

    /// Encrypt an outgoing IP packet, returns WireGuard UDP payload.
    /// Uses the per-peer reusable encrypt buffer.
    pub fn encrypt_packet(&mut self, peer_ip: Ipv4Addr, packet: &[u8]) -> Result<Vec<u8>> {
        // Validate destination IP if packet contains an IPv4 header
        if packet.len() >= 20 {
            let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
            if !self.is_gateway && dst_ip != peer_ip && !dst_ip.is_broadcast() && dst_ip != Ipv4Addr::new(10, 7, 0, 255) {
                warn!("Outgoing packet destination {} does not match peer tunnel IP {}", dst_ip, peer_ip);
            }
        }

        let needed = packet.len() + 32 + 16; // WG header + MACs
        if self.encrypt_buf.len() < needed {
            self.encrypt_buf.resize(needed, 0);
        }

        match self.tunn.encapsulate(packet, &mut self.encrypt_buf) {
            TunnResult::WriteToNetwork(packet_out) => {
                Ok(packet_out.to_vec())
            }
            TunnResult::Err(e) => Err(anyhow!("Encapsulation error: {:?}", e)),
            _ => Err(anyhow!("Failed to encapsulate packet")),
        }
    }

    /// Decrypt incoming WireGuard UDP data with strict Cryptokey Routing verification.
    /// Uses the per-peer reusable decrypt buffer.
    pub fn decrypt_packet(
        &mut self,
        peer_ip: Ipv4Addr,
        src_addr: std::net::SocketAddr,
        data: &[u8],
        network: u32,
        netmask: u32,
    ) -> Result<Vec<DecapsulateOutput>> {
        let mut outputs = Vec::new();
        let mut input_data: Option<&[u8]> = Some(data);

        loop {
            let actual_data = input_data.take().unwrap_or(&[]);
            let src_ip = if !actual_data.is_empty() { Some(src_addr.ip()) } else { None };

            match self.tunn.decapsulate(src_ip, actual_data, &mut self.decrypt_buf) {
                TunnResult::WriteToNetwork(packet_out) => {
                    debug!("WG decapsulate produced network packet for {}", peer_ip);
                    outputs.push(DecapsulateOutput::NetworkPacket(packet_out.to_vec()));
                    // Continue looping — there may be more chained results
                }
                TunnResult::WriteToTunnelV4(packet_out, _) => {
                    // Cryptokey Routing enforcement: Verify source IPv4 address
                    if packet_out.len() < 20 {
                        warn!("Dropped runt IPv4 packet: size {} < 20", packet_out.len());
                    } else {
                        let src_ip_bytes = [packet_out[12], packet_out[13], packet_out[14], packet_out[15]];
                        let src_ip_pkt = Ipv4Addr::from(src_ip_bytes);
                        let src_ip_u32 = u32::from_be_bytes(src_ip_bytes);

                        let is_src_valid = if self.is_gateway {
                            // Packets relayed through a gateway must belong to the virtual subnet and not be broadcast
                            (src_ip_u32 & netmask) == network && !src_ip_pkt.is_broadcast()
                        } else {
                            // Direct peer: source IP must strictly match assigned peer IP
                            src_ip_pkt == peer_ip
                        };

                        if !is_src_valid {
                            warn!("Cryptokey routing violation: dropped spoofed packet with claimed src {} from peer {} (is_gateway={})", 
                                src_ip_pkt, peer_ip, self.is_gateway);
                        } else {
                            // Anti-Lateral Movement: Verify destination IPv4 address is within virtual subnet
                            // Allow broadcast addresses (255.255.255.255 and subnet broadcast e.g. 10.7.0.255)
                            let dst_ip_bytes = [packet_out[16], packet_out[17], packet_out[18], packet_out[19]];
                            let dst_ip = Ipv4Addr::from(dst_ip_bytes);
                            let dst_ip_u32 = u32::from_be_bytes(dst_ip_bytes);
                            let is_broadcast = dst_ip.is_broadcast() || dst_ip == Ipv4Addr::new(10, 7, 0, 255);

                            if !is_broadcast && (dst_ip_u32 & netmask) != network {
                                warn!("Lateral movement blocked: dropped packet destined for external network {} from peer {}", dst_ip, peer_ip);
                            } else if is_broadcast && !self.broadcast_limiter.allow() {
                                warn!("Broadcast storm rate limit exceeded: dropping broadcast packet from peer {}", peer_ip);
                            } else if is_sensitive_host_port(&packet_out) {
                                warn!("Host service isolation: blocked packet targeting sensitive Windows port from peer {}", peer_ip);
                            } else {
                                let mut pkt = packet_out.to_vec();
                                clamp_tcp_mss(&mut pkt, 1340);
                                outputs.push(DecapsulateOutput::TunnelPacket(pkt));
                            }
                        }
                    }
                    // Continue looping — there may be more chained results
                }
                TunnResult::WriteToTunnelV6(_, _) => {
                    warn!("Dropped IPv6 packet: only IPv4 is supported in this virtual LAN");
                    // Continue looping
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    if outputs.is_empty() {
                        return Err(anyhow!("Decapsulation error: {:?}", e));
                    }
                    break;
                }
            }
        }

        Ok(outputs)
    }

    /// Handle WireGuard timer for this peer. Returns an optional packet to send.
    pub fn update_timers(&mut self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 1024];
        match self.tunn.update_timers(&mut buf) {
            TunnResult::WriteToNetwork(packet_out) => {
                Some(packet_out.to_vec())
            }
            _ => None,
        }
    }

    /// Direct access to the underlying Tunn for handshake operations.
    pub fn tunn_mut(&mut self) -> &mut Tunn {
        &mut self.tunn
    }
}

/// Manages WireGuard tunnels for peers.
///
/// Each peer gets its own `Arc<Mutex<PeerTunnel>>` so that:
/// - Encrypt/decrypt for different peers can run concurrently
/// - The manager itself only needs a read-lock for peer lookup
/// - Write-lock is only needed when adding/removing peers (rare)
pub struct WireGuardManager {
    peers: HashMap<Ipv4Addr, Arc<Mutex<PeerTunnel>>>,
    pub network: u32,
    pub netmask: u32,
    rate_limiter: Option<std::sync::Arc<boringtun::noise::rate_limiter::RateLimiter>>,
}

static TUNNEL_INDEX_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

/// Check if an IPv4 packet targets sensitive Windows system services (SMB, RPC, RDP, NetBIOS, WinRM)
pub fn is_sensitive_host_port(packet: &[u8]) -> bool {
    if packet.len() < 20 { return false; }
    let ihl = ((packet[0] & 0x0F) * 4) as usize;
    if packet.len() < ihl + 4 { return false; }
    
    let proto = packet[9];
    if proto != 6 && proto != 17 { // Only TCP and UDP have transport ports
        return false;
    }
    
    let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
    matches!(dst_port, 135 | 137 | 138 | 139 | 445 | 3389 | 5353 | 5355 | 5985 | 5986)
}

/// Clamps TCP MSS option to max_mss (e.g. 1340 bytes) on TCP SYN packets and updates checksum via RFC 1624
pub fn clamp_tcp_mss(packet: &mut [u8], max_mss: u16) {
    if packet.len() < 40 { return; }
    let ihl = ((packet[0] & 0x0F) * 4) as usize;
    let proto = packet[9];
    if proto != 6 || packet.len() < ihl + 20 { return; }

    let tcp_data_offset = ((packet[ihl + 12] >> 4) * 4) as usize;
    let flags = packet[ihl + 13];

    // Only process SYN packets (SYN=1)
    if (flags & 0x02) == 0 { return; }
    if packet.len() < ihl + tcp_data_offset { return; }

    let mut opt_idx = ihl + 20;
    let opt_end = ihl + tcp_data_offset;

    while opt_idx + 1 < opt_end {
        let kind = packet[opt_idx];
        if kind == 0 { break; } // End of option list
        if kind == 1 { opt_idx += 1; continue; } // NOP
        
        let len = packet[opt_idx + 1] as usize;
        if len < 2 || opt_idx + len > opt_end { break; }

        if kind == 2 && len == 4 { // MSS Option
            let old_mss = u16::from_be_bytes([packet[opt_idx + 2], packet[opt_idx + 3]]);
            if old_mss > max_mss {
                let new_mss = max_mss;
                packet[opt_idx + 2..opt_idx + 4].copy_from_slice(&new_mss.to_be_bytes());

                // RFC 1624 incremental checksum update:
                // HC' = ~(~HC + ~m + m')
                let old_csum = u16::from_be_bytes([packet[ihl + 16], packet[ihl + 17]]);
                let mut sum = (!old_csum as u32) + (!old_mss as u32) + (new_mss as u32);
                while (sum >> 16) != 0 {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                let new_csum = !(sum as u16);
                packet[ihl + 16..ihl + 18].copy_from_slice(&new_csum.to_be_bytes());
            }
            break;
        }
        opt_idx += len;
    }
}

impl WireGuardManager {
    /// Create a new WireGuardManager
    pub fn new(subnet: &str) -> Result<Self> {
        let (network, netmask) = Self::parse_cidr(subnet)?;
        Ok(Self {
            peers: HashMap::new(),
            network,
            netmask,
            rate_limiter: None,
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

    /// Creates a Tunn for a peer with a unique incremental local index
    pub fn create_tunnel(
        &mut self,
        own_private_key: &StaticSecret,
        peer_public_key: &PublicKey,
        peer_ip: Ipv4Addr,
        is_gateway: bool,
    ) -> Result<()> {
        info!("Creating tunnel for peer: {} (gateway: {})", peer_ip, is_gateway);
        if self.rate_limiter.is_none() {
            let pub_key = PublicKey::from(own_private_key);
            self.rate_limiter = Some(std::sync::Arc::new(boringtun::noise::rate_limiter::RateLimiter::new(&pub_key, 100)));
        }

        let local_index = TUNNEL_INDEX_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let tunn = Tunn::new(
            own_private_key.clone(),
            *peer_public_key,
            None,
            Some(25), // 25 second keepalive
            local_index,
            self.rate_limiter.clone(),
        );

        self.peers.insert(peer_ip, Arc::new(Mutex::new(PeerTunnel::new(tunn, is_gateway))));
        Ok(())
    }

    /// Get a handle to a peer's tunnel. Cheap — just a HashMap lookup, no crypto.
    /// The caller can then lock the peer independently.
    pub fn get_peer(&self, peer_ip: Ipv4Addr) -> Option<Arc<Mutex<PeerTunnel>>> {
        self.peers.get(&peer_ip).cloned()
    }

    /// Removes a peer from the WireGuard manager.
    pub fn remove_peer(&mut self, peer_ip: Ipv4Addr) {
        self.peers.remove(&peer_ip);
    }

    /// Called periodically to handle WireGuard timers for all peers.
    pub async fn handle_timer(&self) -> Vec<(Ipv4Addr, Vec<u8>)> {
        let mut timer_packets = Vec::new();
        for (&ip, peer) in self.peers.iter() {
            let mut pt = peer.lock().await;
            if let Some(packet) = pt.update_timers() {
                trace!("Timer triggered network write for {}", ip);
                timer_packets.push((ip, packet));
            }
        }
        timer_packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::x25519::{StaticSecret, PublicKey};
    use std::net::Ipv4Addr;

    #[test]
    fn test_broadcast_rate_limiter_burst_and_throttle() {
        let mut limiter = BroadcastRateLimiter::new(10.0, 5.0);
        // Can burst 10 times immediately
        for _ in 0..10 {
            assert!(limiter.allow());
        }
        // 11th should be denied
        assert!(!limiter.allow());
    }

    #[test]
    fn test_create_tunnel_gateway_and_direct() {
        let mut wg_mgr = WireGuardManager::new("10.7.0.0/24").unwrap();
        let peer_ip = Ipv4Addr::new(10, 7, 0, 2);
        
        let secret = StaticSecret::from([1u8; 32]);
        let pub_key = PublicKey::from(&secret);
        
        // Direct peer (Host side)
        wg_mgr.create_tunnel(&secret, &pub_key, peer_ip, false).unwrap();
        assert!(wg_mgr.peers.contains_key(&peer_ip));

        // Gateway peer (Client side)
        let host_ip = Ipv4Addr::new(10, 7, 0, 1);
        wg_mgr.create_tunnel(&secret, &pub_key, host_ip, true).unwrap();
        assert!(wg_mgr.peers.contains_key(&host_ip));
    }

    #[test]
    fn test_is_sensitive_host_port() {
        // Construct dummy IPv4 TCP packet targeting port 445 (SMB)
        let mut smb_pkt = vec![0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1];
        smb_pkt.extend_from_slice(&[0x1F, 0x90, 0x01, 0xBD]); // Src port 8080, Dst port 445
        smb_pkt.extend_from_slice(&[0; 16]); // Rest of TCP header
        assert!(is_sensitive_host_port(&smb_pkt));

        // Construct dummy IPv4 UDP packet targeting game port 27015
        let mut game_pkt = vec![0x45, 0x00, 0x00, 0x20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 10, 7, 0, 1];
        game_pkt.extend_from_slice(&[0x1F, 0x90, 0x69, 0x87]); // Src port 8080, Dst port 27015
        assert!(!is_sensitive_host_port(&game_pkt));
    }
}
