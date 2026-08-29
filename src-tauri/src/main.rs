// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(dead_code, unused_variables, unused_imports)]

mod config;
mod network;
mod room;

use config::ElysiumConfig;
use room::{Room, RoomManager};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{Manager, State};
use tokio::sync::Mutex;
use tracing::{error, info};

/// Shared application state accessible from Tauri commands
pub struct AppState {
    config: Arc<Mutex<ElysiumConfig>>,
    room_manager: Arc<Mutex<RoomManager>>,
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
    drop(config);

    let mut rm = state.room_manager.lock().await;
    if rm.get_active_room().is_some() {
        return Err("You must leave your current room before creating a new one".to_string());
    }

    let room = Room::create_room(public_key, node_name)
        .map_err(|e| format!("Failed to create room: {}", e))?;
    let room_code = room.room_code.clone();

    rm.set_active_room(room);

    info!("Created room: {}", room_code);
    Ok(room_code)
}

/// Join an existing room by invite code
#[tauri::command]
async fn join_room(code: String, state: State<'_, AppState>) -> Result<String, String> {
    info!("Attempting to join room: {}", code);

    // Validate room code format
    Room::validate_room_code(&code).map_err(|e| format!("Invalid room code: {}", e))?;

    // For v1, create a local room representation
    // In a full implementation, this would connect via iroh to the host
    let config = state.config.lock().await;
    let public_key = config
        .get_public_key_base64()
        .map_err(|e| format!("Failed to get public key: {}", e))?;
    let node_name = config.node_name.clone();
    drop(config);

    let mut rm = state.room_manager.lock().await;
    if let Some(active) = rm.get_active_room() {
        if active.room_code == code {
            return Err("You are already in this room".to_string());
        } else {
            return Err("You must leave your current room before joining another".to_string());
        }
    }

    // Placeholder: create a local room with the given code
    let mut room = Room::create_room("host-placeholder".to_string(), "Host".to_string()).unwrap();
    room.room_code = code.clone();

    let ip = room
        .join_room(public_key, node_name)
        .map_err(|e| format!("Failed to join room: {}", e))?;

    rm.set_active_room(room);

    info!("Joined room {} with IP {}", code, ip);
    Ok(ip.to_string())
}

/// Leave the current room
#[tauri::command]
async fn leave_room(state: State<'_, AppState>) -> Result<(), String> {
    let mut rm = state.room_manager.lock().await;
    rm.clear_active_room();
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

        // Find our IP in the room
        let our_ip = room
            .peers
            .iter()
            .find(|p| p.node_name == node_name)
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
