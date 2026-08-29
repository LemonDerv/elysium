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

        // Packet forwarding loop placeholder
        // Normally you would spawn a task to process packet_rx
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

                    let mut wg = wg_mgr.write().await;
                    for (ip, conn) in targets {
                        if let Ok(encrypted) = wg.encrypt_packet(ip, &packet) {
                            let _ = conn.send_datagram(encrypted.into());
                        }
                    }
                }
            }
        });
        
        let wg_mgr2 = self.wg_manager.clone();
        let conns2 = self.connections.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            let mut tick_count = 0;
            loop {
                interval.tick().await;
                tick_count += 1;
                
                let mut wg = wg_mgr2.write().await;
                let packets = wg.handle_timer();
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
                
                // Send Ping every 2 seconds
                if tick_count % 4 == 0 {
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                    let mut ping = vec![255];
                    ping.extend_from_slice(&now.to_be_bytes());
                    for (_, conn) in c.iter() {
                        let _ = conn.send_datagram(ping.clone().into());
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
        
        tokio::spawn(async move {
            while let Ok(datagram) = conn.read_datagram().await {
                if datagram.is_empty() { continue; }
                
                // Ping request (255 + 8 bytes timestamp)
                if datagram[0] == 255 && datagram.len() == 9 {
                    let mut reply = vec![254];
                    reply.extend_from_slice(&datagram[1..]);
                    let _ = conn.send_datagram(reply.into());
                    continue;
                }
                
                // Pong reply (254 + 8 bytes timestamp)
                if datagram[0] == 254 && datagram.len() == 9 {
                    let mut ts_bytes = [0u8; 8];
                    ts_bytes.copy_from_slice(&datagram[1..]);
                    let sent_ts = u64::from_be_bytes(ts_bytes);
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
                    if now >= sent_ts {
                        let rtt = (now - sent_ts) as f64;
                        let mut rm = room_manager_recv.lock().await;
                        if let Some(room) = rm.get_active_room_mut() {
                            if let Some(peer) = room.peers.iter_mut().find(|p| p.virtual_ip == peer_ip) {
                                peer.latency_ms = Some(rtt);
                            }
                        }
                    }
                    continue;
                }

                // Use a dummy address since Wireguard decrypt doesn't strictly need the correct UDP source 
                // when we manage the routing per-connection manually.
                let src_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
                let mut wg = wg_mgr.write().await;
                if let Ok(outputs) = wg.decrypt_packet(peer_ip, src_addr, &datagram) {
                    drop(wg);
                    for output in outputs {
                        match output {
                            crate::network::wireguard::DecapsulateOutput::TunnelPacket(decrypted) => {
                                let t = tunnel.lock().await;
                                let _ = t.write_packet(&decrypted);
                            }
                            crate::network::wireguard::DecapsulateOutput::NetworkPacket(response) => {
                                let _ = conn.send_datagram(response.into());
                            }
                            crate::network::wireguard::DecapsulateOutput::Done => {}
                        }
                    }
                }
            }
        });
    }
}
