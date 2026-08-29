// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(dead_code, unused_variables, unused_imports)]

mod network;
mod room;
mod config;

use base64::Engine;
use config::ElysiumConfig;
use room::{Room, RoomManager};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Manager, State};
use tokio::sync::Mutex;
use tracing::{error, info};

use network::NetworkEngine;

/// Shared application state accessible from Tauri commands
pub struct AppState {
    config: Arc<Mutex<ElysiumConfig>>,
    room_manager: Arc<Mutex<RoomManager>>,
    network_engine: Arc<Mutex<Option<NetworkEngine>>>,
}

/// Status info returned to the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub connected: bool,
    pub node_name: String,
    pub public_key: String,
    pub room_code: Option<String>,
    pub virtual_ip: Option<String>,
    pub peers: Vec<PeerStatus>,
}

/// Peer status for the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub node_name: String,
    pub virtual_ip: String,
    pub latency_ms: Option<f64>,
    pub connected: bool,
}

/// Create a new room and return the room code
#[tauri::command]
async fn create_room(state: State<'_, AppState>) -> Result<String, String> {
    let config = state.config.lock().await;
    let public_key = config
        .get_public_key_base64()
        .map_err(|e| format!("Failed to get public key: {}", e))?;
    let node_name = config.node_name.clone();
    let subnet = config.virtual_subnet.clone();
    let secret_key = config.get_keypair().map_err(|e| e.to_string())?;
    drop(config);

    let mut rm = state.room_manager.lock().await;
    if rm.get_active_room().is_some() {
        return Err("You must leave your current room before creating a new one".to_string());
    }

    let peer_manager = network::peer::PeerManager::init().await.map_err(|e| e.to_string())?;
    let addr = peer_manager.get_addr();

    let room = Room::create_room(public_key.clone(), node_name.clone(), &addr)
        .map_err(|e| format!("Failed to create room: {}", e))?;
    let room_code = room.room_code.clone();

    let host_ip = room.peers[0].virtual_ip;

    rm.set_active_room(room);
    drop(rm);

    // Initialize NetworkEngine
    let tunnel = network::tunnel::TunnelManager::create_adapter("ElysiumLAN").map_err(|e| e.to_string())?;
    tunnel.set_ip(host_ip, std::net::Ipv4Addr::new(255, 255, 255, 0)).map_err(|e| e.to_string())?;
    
    let wg = network::wireguard::WireGuardManager::new(&subnet).map_err(|e| e.to_string())?;
    let engine = network::NetworkEngine::new(tunnel, wg, peer_manager, state.room_manager.clone());
    engine.start().await.map_err(|e| e.to_string())?;

    // Store in AppState
    let mut ne = state.network_engine.lock().await;
    *ne = Some(engine);
    drop(ne);
    
    // Start accepting connections
    let ne_clone = state.network_engine.clone();
    let rm_clone = state.room_manager.clone();
    let sk = secret_key.clone();
    let host_public_key = public_key.clone();
    let host_node_name = node_name.clone();
    
    tokio::spawn(async move {
        let engine = {
            let n = ne_clone.lock().await;
            if let Some(e) = n.as_ref() {
                e.peer_manager.clone()
            } else { return; }
        };
        
        let ep = engine.endpoint.clone();
        while let Some(incoming) = ep.accept().await {
            match incoming.accept() {
                Ok(accepting) => match accepting.await {
                    Ok(conn) => {
                        let remote_id = conn.remote_id();
                        info!("Accepted connection from {}", remote_id);
                        
                        // Wait for exchange info from joining client
                        if let Ok(peer_info) = network::discovery::DiscoveryService::exchange_peer_info_host(&conn).await {
                            // Add peer to Room and allocate IP
                            let mut rm = rm_clone.lock().await;
                            if let Some(room) = rm.get_active_room_mut() {
                                if let Ok(ip) = room.join_room(peer_info.wg_public_key.clone(), peer_info.node_name.clone()) {
                                    // Reply with HOST's info and the allocated IP
                                    let response = network::discovery::PeerExchangeInfo {
                                        wg_public_key: host_public_key.clone(),
                                        virtual_ip: ip,
                                        udp_endpoints: vec![],
                                        node_name: host_node_name.clone(),
                                    };
                                    drop(rm);
                                    let _ = network::discovery::DiscoveryService::send_peer_info_response(&conn, response).await;
                                    
                                    // Setup WG tunnel for this peer
                                    let n = ne_clone.lock().await;
                                    if let Some(e) = n.as_ref() {
                                        let decoded = base64::engine::general_purpose::STANDARD.decode(&peer_info.wg_public_key).unwrap();
                                        let mut bytes = [0u8; 32];
                                        bytes.copy_from_slice(&decoded);
                                        let peer_pk = boringtun::x25519::PublicKey::from(bytes);
                                        
                                        let mut wg = e.wg_manager.write().await;
                                        let _ = wg.create_tunnel(&sk, &peer_pk, ip);
                                        drop(wg);
                                        
                                        e.add_connection(ip, conn).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => error!("Failed to establish accepted connection: {}", e),
                },
                Err(e) => error!("Failed to accept incoming: {}", e),
            }
        }
    });

    info!("Created room: {}", room_code);
    Ok(room_code)
}

/// Join an existing room by invite code
#[tauri::command]
async fn join_room(code: String, state: State<'_, AppState>) -> Result<String, String> {
    info!("Attempting to join room: {}", code);

    Room::validate_room_code(&code).map_err(|e| format!("Invalid room code: {}", e))?;

    let decoded = base64::engine::general_purpose::STANDARD.decode(code.trim()).unwrap();
    let host_addr: iroh::EndpointAddr = serde_json::from_slice(&decoded).unwrap();

    let config = state.config.lock().await;
    let public_key = config.get_public_key_base64().map_err(|e| e.to_string())?;
    let node_name = config.node_name.clone();
    let subnet = config.virtual_subnet.clone();
    let secret_key = config.get_keypair().map_err(|e| e.to_string())?;
    drop(config);

    let mut rm = state.room_manager.lock().await;
    if rm.get_active_room().is_some() {
        return Err("You must leave your current room before joining another".to_string());
    }

    let peer_manager = network::peer::PeerManager::init().await.map_err(|e| e.to_string())?;
    
    let conn = peer_manager.connect_to_peer(host_addr, network::peer::ALPN)
        .await.map_err(|e| e.to_string())?;

    let our_info = network::discovery::PeerExchangeInfo {
        wg_public_key: public_key.clone(),
        virtual_ip: std::net::Ipv4Addr::new(0, 0, 0, 0), // Host assigns IP
        udp_endpoints: vec![],
        node_name: node_name.clone(),
    };
    
    let response = network::discovery::DiscoveryService::exchange_peer_info_client(&conn, our_info).await.map_err(|e| e.to_string())?;
    
    // We now have our IP assigned by host
    let ip = response.virtual_ip;

    // Create a local room object
    let mut room = Room::create_room("host-placeholder".to_string(), "Host".to_string(), &peer_manager.get_addr()).unwrap();
    room.room_code = code.clone();
    let host_ip = room.peers[0].virtual_ip;
    room.peers.push(room::PeerInfo {
        public_key: public_key,
        virtual_ip: ip,
        node_name,
        latency_ms: None,
        connected: true,
    });
    rm.set_active_room(room);
    drop(rm);

    // Start networking
    let tunnel = network::tunnel::TunnelManager::create_adapter("ElysiumLAN").map_err(|e| e.to_string())?;
    tunnel.set_ip(ip, std::net::Ipv4Addr::new(255, 255, 255, 0)).map_err(|e| e.to_string())?;
    
    let wg = network::wireguard::WireGuardManager::new(&subnet).map_err(|e| e.to_string())?;
    let engine = network::NetworkEngine::new(tunnel, wg, peer_manager, state.room_manager.clone());
    
    // Host has a placeholder PK in our local room, but for WG we don't know it.
    // Wait, the host should send their PK in the response! 
    // We need to update PeerExchangeInfo and DiscoveryService logic. Let's assume response.wg_public_key is the host's PK.
    
    let host_pk_decoded = base64::engine::general_purpose::STANDARD.decode(&response.wg_public_key).unwrap();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&host_pk_decoded);
    let host_pk = boringtun::x25519::PublicKey::from(bytes);
    
    {
        let mut wg_write = engine.wg_manager.write().await;
        let _ = wg_write.create_tunnel(&secret_key, &host_pk, host_ip);
    }
    
    engine.start().await.map_err(|e| e.to_string())?;
    engine.add_connection(host_ip, conn).await;

    let mut ne = state.network_engine.lock().await;
    *ne = Some(engine);
    drop(ne);

    info!("Joined room {} with IP {}", code, ip);
    Ok(ip.to_string())
}

/// Leave the current room
#[tauri::command]
async fn leave_room(state: State<'_, AppState>) -> Result<(), String> {
    let mut rm = state.room_manager.lock().await;
    rm.clear_active_room();
    
    let mut ne = state.network_engine.lock().await;
    if let Some(engine) = ne.take() {
        let _ = engine.stop().await;
    }
    info!("Left room");
    Ok(())
}

/// Get current status
#[tauri::command]
async fn get_status(state: State<'_, AppState>) -> Result<StatusInfo, String> {
    let config = state.config.lock().await;
    let public_key = config
        .get_public_key_base64()
        .unwrap_or_else(|_| "unknown".to_string());
    let node_name = config.node_name.clone();
    drop(config);

    let rm = state.room_manager.lock().await;

    let (connected, room_code, virtual_ip, peers) = if let Some(room) = rm.get_active_room() {
        let peers: Vec<PeerStatus> = room
            .peers
            .iter()
            .map(|p| PeerStatus {
                node_name: p.node_name.clone(),
                virtual_ip: p.virtual_ip.to_string(),
                latency_ms: p.latency_ms,
                connected: p.connected,
            })
            .collect();

        // Find our IP in the room using cryptographic identity
        let our_ip = room
            .peers
            .iter()
            .find(|p| p.public_key == public_key)
            .map(|p| p.virtual_ip.to_string());

        (true, Some(room.room_code.clone()), our_ip, peers)
    } else {
        (false, None, None, vec![])
    };

    Ok(StatusInfo {
        connected,
        node_name,
        public_key,
        room_code,
        virtual_ip,
        peers,
    })
}

/// Get the list of known rooms from config
#[tauri::command]
async fn get_known_rooms(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let config = state.config.lock().await;
    let rooms: Vec<String> = config.known_rooms.keys().cloned().collect();
    Ok(rooms)
}

fn main() {
    // Add firewall rule for the app
    if let Ok(exe_path) = std::env::current_exe() {
        let _ = std::process::Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                "name=Elysium LAN",
                "dir=in", "action=allow",
                &format!("program={}", exe_path.display()),
                "enable=yes"
            ])
            .status();
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting Elysium v{}", env!("CARGO_PKG_VERSION"));

    // Load or create config
    let config = ElysiumConfig::load_or_create().unwrap_or_else(|e| {
        error!("Failed to load config, using defaults: {}", e);
        ElysiumConfig::default()
    });

    info!("Node name: {}", config.node_name);

    let app_state = AppState {
        config: Arc::new(Mutex::new(config)),
        room_manager: Arc::new(Mutex::new(RoomManager::new())),
        network_engine: Arc::new(Mutex::new(None)),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            create_room,
            join_room,
            leave_room,
            get_status,
            get_known_rooms,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
