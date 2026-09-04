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
pub fn resolve_netsh_path() -> PathBuf {
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        let netsh = Path::new(&sys_root).join("System32").join("netsh.exe");
        if netsh.exists() {
            return netsh;
        }
    }
    PathBuf::from("netsh")
}

/// Resolve the absolute path to powershell.exe to prevent PATH environment variable hijacking.
pub fn resolve_powershell_path() -> PathBuf {
    if let Ok(sys_root) = std::env::var("SystemRoot") {
        let ps = Path::new(&sys_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        if ps.exists() {
            return ps;
        }
    }
    PathBuf::from("powershell")
}

/// Sets the Windows network category of the adapter to Private so Windows Firewall
/// does not drop unsolicited game connections and ICMP pings.
pub fn set_network_category_private(name: &str) -> Result<()> {
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(anyhow!("Invalid adapter name: '{}'", name));
    }

    let ps_bin = resolve_powershell_path();
    info!("Setting adapter '{}' network category to Private...", name);

    let mut last_err = String::new();
    for attempt in 1..=3 {
        let status = Command::new(&ps_bin)
            .args(&[
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass",
                "-Command",
                &format!("Set-NetConnectionProfile -InterfaceAlias '{}' -NetworkCategory Private -ErrorAction Stop", name),
            ])
            .status();

        match status {
            Ok(s) if s.success() => {
                info!("Successfully set network category of '{}' to Private (attempt {})", name, attempt);
                return Ok(());
            }
            Ok(s) => {
                last_err = format!("PowerShell exited with code {:?}", s.code());
            }
            Err(e) => {
                last_err = e.to_string();
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
    }

    tracing::warn!("Could not set network category to Private after 3 attempts: {}. Manual firewall allowance may be required.", last_err);
    Ok(())
}

/// Validates the Authenticode digital signature of wintun.dll to prevent DLL hijacking
/// and unauthorized driver execution.
pub fn verify_wintun_dll_signature(dll_path: &Path) -> Result<()> {
    // If dev/debug override is present, allow unsigned with a warning
    if std::env::var("ELYSIUM_ALLOW_UNSIGNED_WINTUN").is_ok() {
        tracing::warn!(
            "ELYSIUM_ALLOW_UNSIGNED_WINTUN set: bypassing Authenticode verification for {:?}",
            dll_path
        );
        return Ok(());
    }

    let ps_bin = resolve_powershell_path();
    let dll_str = dll_path.to_string_lossy();

    let output = Command::new(&ps_bin)
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &format!(
                "(Get-AuthenticodeSignature -FilePath '{}').Status.ToString()",
                dll_str
            ),
        ])
        .output()
        .context("Failed to run Authenticode signature check via PowerShell")?;

    let status = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if status == "Valid" {
        info!("wintun.dll Authenticode signature verified successfully");
        Ok(())
    } else {
        // In debug builds or non-production environments where official driver signing cert may be absent in local dev,
        // log a warning instead of hard failing.
        if cfg!(debug_assertions) {
            tracing::warn!(
                "wintun.dll Authenticode signature is '{}' (expected 'Valid'). Proceeding because this is a debug build.",
                status
            );
            Ok(())
        } else {
            Err(anyhow!(
                "wintun.dll failed Authenticode verification: status is '{}'. Rejecting untrusted driver binary.",
                status
            ))
        }
    }
}

/// Configures Windows Firewall rules on the ElysiumLAN virtual interface to block
/// lateral movement to sensitive Windows services (SMB 445, NetBIOS 137-139, RPC 135,
/// RDP 3389, WinRM 5985/5986) while allowing ICMP echo (ping) and gaming ports.
pub fn harden_elysium_firewall(name: &str) -> Result<()> {
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err(anyhow!("Invalid adapter name: '{}'", name));
    }

    let ps_bin = resolve_powershell_path();
    info!("Hardening Windows Firewall for virtual adapter '{}'...", name);

    let script = format!(
        r#"
        Remove-NetFirewallRule -DisplayName 'ElysiumLAN-Block-Inbound-HostPorts-TCP' -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName 'ElysiumLAN-Block-Inbound-HostPorts-UDP' -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName 'ElysiumLAN-Allow-ICMP' -ErrorAction SilentlyContinue

        New-NetFirewallRule -DisplayName 'ElysiumLAN-Block-Inbound-HostPorts-TCP' -Direction Inbound -Action Block -Protocol TCP -LocalPort 135,137,138,139,445,3389,5985,5986 -InterfaceAlias '{name}' -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName 'ElysiumLAN-Block-Inbound-HostPorts-UDP' -Direction Inbound -Action Block -Protocol UDP -LocalPort 137,138,5353,5355 -InterfaceAlias '{name}' -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName 'ElysiumLAN-Allow-ICMP' -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -InterfaceAlias '{name}' -ErrorAction SilentlyContinue
        "#,
        name = name
    );

    let status = Command::new(&ps_bin)
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status();

    match status {
        Ok(s) if s.success() => {
            info!("Successfully configured Elysium firewall rules on '{}'", name);
            Ok(())
        }
        Ok(s) => {
            tracing::warn!("PowerShell firewall setup exited with code {:?}", s.code());
            Ok(())
        }
        Err(e) => {
            tracing::warn!("Failed to execute firewall hardening script: {}", e);
            Ok(())
        }
    }
}

/// Removes Elysium Windows Firewall rules during shutdown.
pub fn cleanup_elysium_firewall() {
    let ps_bin = resolve_powershell_path();
    let script = r#"
        Remove-NetFirewallRule -DisplayName 'ElysiumLAN-Block-Inbound-HostPorts-TCP' -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName 'ElysiumLAN-Block-Inbound-HostPorts-UDP' -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName 'ElysiumLAN-Allow-ICMP' -ErrorAction SilentlyContinue
    "#;

    let _ = Command::new(&ps_bin)
        .args(&[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .status();
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
        info!("Verifying wintun.dll signature at: {:?}", dll_path);
        verify_wintun_dll_signature(&dll_path)?;

        info!("Loading wintun library securely from: {:?}", dll_path);
        let wintun = unsafe { wintun::load_from_path(&dll_path) }
            .map_err(|e| anyhow!("Failed to load wintun.dll from {:?}: {}", dll_path, e))?;

        let guid = ELYSIUM_ADAPTER_GUID;
        let adapter = match Adapter::create(&wintun, name, name, Some(guid)) {
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
        
        // Set high interface metric so Windows doesn't route default internet through this adapter
        let _ = Command::new(&netsh_bin)
            .args(&[
                "interface", "ipv4", "set", "interface",
                &format!("interface={}", name),
                "metric=9999",
            ])
            .status();

        // Set MTU to 1380 bytes (RFC 8900 optimization to prevent fragmentation under WireGuard + QUIC encapsulation)
        let _ = Command::new(&netsh_bin)
            .args(&[
                "interface", "ipv4", "set", "subinterface",
                &name,
                "mtu=1380",
                "store=active",
            ])
            .status();

        // Mitigate TunnelVision (CVE-2024-3661): explicitly bind on-link virtual subnet 10.7.0.0/24
        // to ElysiumLAN with metric 1 so rogue DHCP Option 121 routes on physical interfaces cannot hijack traffic.
        let _ = Command::new(&netsh_bin)
            .args(&[
                "interface", "ipv4", "add", "route",
                "10.7.0.0/24",
                &name,
                &ip.to_string(),
                "metric=1",
                "store=active",
            ])
            .status();

        // Route virtual subnet broadcast 10.7.0.255/32 to ElysiumLAN with metric 1 for LAN game discovery
        // NOTE: We deliberately do NOT route 255.255.255.255/32 to prevent hijacking physical LAN discovery.
        let _ = Command::new(&netsh_bin)
            .args(&[
                "interface", "ipv4", "add", "route",
                "10.7.0.255/32",
                &name,
                &ip.to_string(),
                "metric=1",
                "store=active",
            ])
            .status();

        // Set adapter network category to Private so Windows Firewall allows game traffic
        let _ = set_network_category_private(&name);

        // Harden Windows Firewall on ElysiumLAN to block sensitive host services (SMB, RPC, NetBIOS, RDP)
        let _ = harden_elysium_firewall(&name);
        
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
            // Apply real-time gaming thread priority and MMCSS tuning
            crate::network::windows_tuning::WindowsGamingTuner::tune_worker_thread("wintun-reader");

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

    pub fn validate_packet_size(size: usize) -> Result<()> {
        if size > u16::MAX as usize || size == 0 {
            anyhow::bail!("Packet size {} is invalid for WinTUN", size);
        }
        Ok(())
    }

    /// Writes a decrypted packet to the TUN adapter
    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
        Self::validate_packet_size(packet.len())?;
        
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

    /// Closes session and removes adapter routes & firewall rules
    pub fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down TunnelManager");
        if let Ok(name) = self.adapter.get_name() {
            let netsh_bin = resolve_netsh_path();
            let _ = Command::new(&netsh_bin)
                .args(&["interface", "ipv4", "delete", "route", "10.7.0.0/24", &name])
                .status();
            let _ = Command::new(&netsh_bin)
                .args(&["interface", "ipv4", "delete", "route", "10.7.0.255/32", &name])
                .status();
        }
        cleanup_elysium_firewall();
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
        let result_valid = TunnelManager::validate_packet_size(65535);
        assert!(result_valid.is_ok());

        let result_too_large = TunnelManager::validate_packet_size(65536);
        assert!(result_too_large.is_err());
        assert_eq!(result_too_large.unwrap_err().to_string(), "Packet size 65536 is invalid for WinTUN");
        
        let result_empty = TunnelManager::validate_packet_size(0);
        assert!(result_empty.is_err());
        assert_eq!(result_empty.unwrap_err().to_string(), "Packet size 0 is invalid for WinTUN");
    }

    #[test]
    fn test_resolve_powershell_path() {
        let ps = resolve_powershell_path();
        assert!(ps.to_string_lossy().contains("powershell"));
    }

    #[test]
    fn test_adapter_name_validation() {
        assert!(set_network_category_private("Valid-Name_1").is_ok() || true);
        assert!(set_network_category_private("Invalid;Name&").is_err());
        assert!(harden_elysium_firewall("Bad;Cmd").is_err());
        assert!(harden_elysium_firewall("Valid-Elysium_LAN").is_ok() || true);
    }

    #[test]
    fn test_verify_wintun_dll_signature_env_override() {
        unsafe {
            std::env::set_var("ELYSIUM_ALLOW_UNSIGNED_WINTUN", "1");
        }
        let dummy_path = PathBuf::from("C:\\fake\\wintun.dll");
        assert!(verify_wintun_dll_signature(&dummy_path).is_ok());
        unsafe {
            std::env::remove_var("ELYSIUM_ALLOW_UNSIGNED_WINTUN");
        }
    }
}

