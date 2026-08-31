use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info};

pub mod discovery;
pub mod nat;
pub mod peer;
pub mod tunnel;
pub mod wireguard;

#[cfg(test)]


use crate::network::peer::PeerManager;
use crate::network::tunnel::TunnelManager;
use crate::network::wireguard::WireGuardManager;

/// Main network engine orchestrating the virtual LAN
pub struct NetworkEngine {
    pub tunnel_manager: Arc<Mutex<TunnelManager>>,
    pub wg_manager: Arc<RwLock<WireGuardManager>>,
    pub peer_manager: Arc<PeerManager>,
    pub packet_tx: mpsc::Sender<Vec<u8>>,
    pub packet_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    pub connections: Arc<RwLock<std::collections::HashMap<std::net::Ipv4Addr, iroh::endpoint::Connection>>>,
    pub room_manager: Arc<Mutex<crate::room::RoomManager>>,
}

impl NetworkEngine {
    /// Create a new NetworkEngine instance
    pub fn new(
        tunnel_manager: TunnelManager,
        wg_manager: WireGuardManager,
        peer_manager: PeerManager,
        room_manager: Arc<Mutex<crate::room::RoomManager>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(1024);
        
        Self {
            tunnel_manager: Arc::new(Mutex::new(tunnel_manager)),
            wg_manager: Arc::new(RwLock::new(wg_manager)),
            peer_manager: Arc::new(peer_manager),
            packet_tx: tx,
            packet_rx: Arc::new(Mutex::new(rx)),
            connections: Arc::new(RwLock::new(std::collections::HashMap::new())),
            room_manager,
        }
    }

    /// Start the network engine packet loop
    pub async fn start(&self) -> Result<()> {
        info!("Starting NetworkEngine");
        
        // Start tunnel reading task
        let mut tm = self.tunnel_manager.lock().await;
        tm.start_reading(self.packet_tx.clone()).await?;

        // Outbound packet forwarding loop (TUN → WireGuard → Iroh)
        let rx = self.packet_rx.clone();
        let wg_mgr = self.wg_manager.clone();
        let connections = self.connections.clone();

        tokio::spawn(async move {
            let mut rx = rx.lock().await;
            while let Some(packet) = rx.recv().await {
                if packet.len() >= 20 {
                    let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                    
                    let is_broadcast = dst_ip.is_broadcast() || dst_ip == std::net::Ipv4Addr::new(10, 7, 0, 255);
                    
                    let mut targets = Vec::new();
                    let conns = connections.read().await;
                    
                    if is_broadcast {
                        for (ip, conn) in conns.iter() {
                            targets.push((*ip, conn.clone()));
                        }
                    } else if let Some(conn) = conns.get(&dst_ip) {
                        targets.push((dst_ip, conn.clone()));
                    }
                    drop(conns);

                    // READ lock on WireGuardManager — just to look up peer handles
                    let wg = wg_mgr.read().await;
                    for (ip, conn) in targets {
                        if let Some(peer) = wg.get_peer(ip) {
                            // Per-peer lock — only blocks if this specific peer is busy
                            let mut pt = peer.lock().await;
                            if let Ok(encrypted) = pt.encrypt_packet(ip, &packet) {
                                let _ = conn.send_datagram(encrypted.into());
                            }
                        }
                    }
                }
            }
        });
        
        // Timer loop (keepalives + ping)
        let wg_mgr2 = self.wg_manager.clone();
        let conns2 = self.connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                interval.tick().await;
                
                // READ lock — handle_timer iterates peers with per-peer locks internally
                let wg = wg_mgr2.read().await;
                let packets = wg.handle_timer().await;
                drop(wg);
                
                let c = conns2.read().await;
                
                // Send Wireguard timers
                if !packets.is_empty() {
                    for (ip, packet) in packets {
                        if let Some(conn) = c.get(&ip) {
                            let _ = conn.send_datagram(packet.into());
                        }
                    }
                }
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

    /// Add a new Iroh connection and start its receive loop
    pub async fn add_connection(&self, peer_ip: std::net::Ipv4Addr, conn: iroh::endpoint::Connection) {
        self.connections.write().await.insert(peer_ip, conn.clone());
        
        let wg_mgr = self.wg_manager.clone();
        let tunnel = self.tunnel_manager.clone();
        let room_manager_recv = self.room_manager.clone();
        let conns = self.connections.clone();
        
        tokio::spawn(async move {
            // Cache network/netmask and peer handle at start — avoids re-locking manager per packet
            let (network, netmask, peer_handle) = {
                let wg = wg_mgr.read().await;
                (wg.network, wg.netmask, wg.get_peer(peer_ip))
            };
            
            let Some(peer_handle) = peer_handle else {
                tracing::error!("No tunnel found for peer {} in add_connection", peer_ip);
                return;
            };

            while let Ok(datagram) = conn.read_datagram().await {
                if datagram.is_empty() { continue; }
                
                // Decrypt with per-peer lock — doesn't block other peers
                let src_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
                let mut pt = peer_handle.lock().await;
                let decrypt_result = pt.decrypt_packet(peer_ip, src_addr, &datagram, network, netmask);
                drop(pt); // Release per-peer lock before doing TUN I/O or Relay
                
                if let Ok(outputs) = decrypt_result {
                    for output in outputs {
                        match output {
                            crate::network::wireguard::DecapsulateOutput::TunnelPacket(decrypted) => {
                                if decrypted.len() >= 20 {
                                    let dst_ip = std::net::Ipv4Addr::new(decrypted[16], decrypted[17], decrypted[18], decrypted[19]);
                                    let is_broadcast = dst_ip.is_broadcast() || dst_ip == std::net::Ipv4Addr::new(10, 7, 0, 255);
                                    let is_host = dst_ip == std::net::Ipv4Addr::new(10, 7, 0, 1);
                                    
                                    if is_broadcast || is_host {
                                        let t = tunnel.lock().await;
                                        let _ = t.write_packet(&decrypted);
                                    } else {
                                        // Relay to another peer (Mesh Virtual Switch)
                                        let c = conns.read().await;
                                        if let Some(dst_conn) = c.get(&dst_ip) {
                                            let dst_conn_clone = dst_conn.clone();
                                            drop(c);
                                            let wg = wg_mgr.read().await;
                                            if let Some(dst_peer) = wg.get_peer(dst_ip) {
                                                let mut dpt = dst_peer.lock().await;
                                                if let Ok(encrypted) = dpt.encrypt_packet(dst_ip, &decrypted) {
                                                    let _ = dst_conn_clone.send_datagram(encrypted.into());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            crate::network::wireguard::DecapsulateOutput::NetworkPacket(response) => {
                                let _ = conn.send_datagram(response.into());
                            }
                            crate::network::wireguard::DecapsulateOutput::Done => {}
                        }
                    }
                }
            }
            
            // Disconnection Cleanup (fixes Ghost Peers and IP Exhaustion)
            tracing::info!("Peer {} disconnected, cleaning up", peer_ip);
            
            let mut c = conns.write().await;
            c.remove(&peer_ip);
            drop(c);
            
            let mut wg = wg_mgr.write().await;
            wg.remove_peer(peer_ip);
            drop(wg);
            
            let mut rm = room_manager_recv.lock().await;
            if let Some(room) = rm.get_active_room_mut() {
                let pk = room.get_peer_by_ip(&peer_ip).map(|p| p.public_key.clone());
                if let Some(k) = pk {
                    let _ = room.remove_peer(&k);
                }
            }
        });
    }
}
