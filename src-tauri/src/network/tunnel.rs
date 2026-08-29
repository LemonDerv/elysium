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

/// Fixed GUID so we always reuse the same adapter instead of creating duplicates
const ELYSIUM_ADAPTER_GUID: u128 = 0xE1_75_10_4D_CA_FE_BA_BE_00_00_00_00_00_00_00_01;

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

        // Try to delete any stale adapter with the same name first
        if let Ok(stale_adapter) = Adapter::open(&wintun, name) {
            let _ = stale_adapter.delete();
        }

        let guid = ELYSIUM_ADAPTER_GUID;
        let adapter = Adapter::create(&wintun, name, name, Some(guid))
            .map_err(|e| anyhow!("Failed to create adapter '{}': {}", name, e))?;

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
        
        // Set the IP address
        let status = Command::new(&netsh_bin)
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
        
        // Set high interface metric so Windows doesn't route internet through this adapter
        let _ = Command::new(&netsh_bin)
            .args(&[
                "interface", "ipv4", "set", "interface",
                &format!("interface={}", name),
                "metric=9999",
            ])
            .status();
        
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
        if packet.len() > u16::MAX as usize || packet.is_empty() {
            anyhow::bail!("Packet size {} is invalid for WinTUN", packet.len());
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vuln4_u16_truncation_rejection() {
        let tunnel_mgr = TunnelManager {
            adapter: unsafe { std::mem::MaybeUninit::zeroed().assume_init() },
            session: None,
        };
        
        let packet_65535 = vec![0u8; 65535];
        let result = tunnel_mgr.write_packet(&packet_65535);
        assert!(result.is_err()); 
        assert_eq!(result.unwrap_err().to_string(), "Session not started");

        let packet_65536 = vec![0u8; 65536];
        let result = tunnel_mgr.write_packet(&packet_65536);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Packet size 65536 is invalid for WinTUN");
        
        let packet_empty = vec![0u8; 0];
        let result = tunnel_mgr.write_packet(&packet_empty);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Packet size 0 is invalid for WinTUN");
        
        // Prevent Drop from running on the zeroed Arc causing Access Violation
        std::mem::forget(tunnel_mgr);
    }
}
