use anyhow::{anyhow, Context, Result};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;
use tracing::{error, info};
use wintun::{Adapter, Session};

/// Locate wintun.dll securely by checking next to the executable first, then System32.
fn resolve_wintun_dll_path() -> Result<PathBuf> {
    // 1. Check next to running executable
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let dll = exe_dir.join("wintun.dll");
            if dll.exists() {
                return Ok(dll);
            }
        }
    }

    // 2. Fallback to System32
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        let sys32_dll = Path::new(&sys_root).join("System32").join("wintun.dll");
        if sys32_dll.exists() {
            return Ok(sys32_dll);
        }
    }

    Err(anyhow!("wintun.dll not found in executable directory or System32"))
}

/// Resolve the absolute path to netsh.exe to prevent PATH environment variable hijacking.
fn resolve_netsh_path() -> PathBuf {
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        let netsh = Path::new(&sys_root).join("System32").join("netsh.exe");
        if netsh.exists() {
            return netsh;
        }
    }
    PathBuf::from("netsh")
}

/// Manages the WinTUN virtual adapter
pub struct TunnelManager {
    adapter: Arc<Adapter>,
    session: Option<Arc<Session>>,
}

impl TunnelManager {
    /// Creates a WinTUN adapter named "Elysium"
    pub fn create_adapter(name: &str) -> Result<Self> {
        // Validate adapter name contains only safe alphanumeric/hyphen characters
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(anyhow!("Invalid adapter name: '{}'", name));
        }

        let dll_path = resolve_wintun_dll_path()?;
        info!("Loading wintun library securely from: {:?}", dll_path);
        let wintun = unsafe { wintun::load_from_path(&dll_path) }
            .map_err(|e| anyhow!("Failed to load wintun.dll from {:?}: {}", dll_path, e))?;

        let adapter = match Adapter::create(&wintun, name, name, None) {
            Ok(a) => a,
            Err(_) => Adapter::open(&wintun, name)
                .map_err(|e| anyhow!("Failed to open existing adapter '{}': {}", name, e))?,
        };

        Ok(Self {
            adapter,
            session: None,
        })
    }

    /// Configures the adapter IP using netsh command
    pub fn set_ip(&self, ip: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
        info!("Setting adapter IP to {} with mask {}", ip, mask);
        let name = self.adapter.get_name().map_err(|e| anyhow!("Failed to get adapter name: {}", e))?;
        
        let netsh_bin = resolve_netsh_path();
        let status = Command::new(netsh_bin)
            .args(&[
                "interface", "ipv4", "set", "address",
                &format!("name={}", name),
                "static",
                &ip.to_string(),
                &mask.to_string(),
            ])
            .status()
            .context("Failed to execute netsh command")?;

        if !status.success() {
            return Err(anyhow!("Failed to set IP via netsh (exit code: {:?})", status.code()));
        }
        Ok(())
    }

    /// Starts a thread that reads packets from TUN and sends to channel
    pub async fn start_reading(&mut self, tx: mpsc::Sender<Vec<u8>>) -> Result<()> {
        let session = Arc::new(
            self.adapter.start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| anyhow!("Failed to start wintun session: {}", e))?
        );
        self.session = Some(session.clone());

        task::spawn_blocking(move || {
            loop {
                match session.receive_blocking() {
                    Ok(packet) => {
                        let data = packet.bytes().to_vec();
                        if let Err(e) = tx.blocking_send(data) {
                            error!("Failed to send packet to channel: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error reading from TUN: {:?}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Writes a decrypted packet to the TUN adapter
    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if let Some(session) = &self.session {
            let mut send_pack = session.allocate_send_packet(packet.len() as u16)
                .map_err(|e| anyhow!("Failed to allocate send packet: {}", e))?;
            send_pack.bytes_mut().copy_from_slice(packet);
            session.send_packet(send_pack);
            Ok(())
        } else {
            Err(anyhow!("Session not started"))
        }
    }

    /// Closes session and removes adapter (cleanup handled mostly by Drop, but explicit here)
    pub fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down TunnelManager");
        self.session = None;
        // Adapter drop will close it
        Ok(())
    }
}
