use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as base64_std, Engine};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{info, warn};

/// Known room information stored in the configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownRoom {
    pub room_code: String,
    pub last_joined: u64, // Unix timestamp
}

/// The main application configuration for Elysium.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElysiumConfig {
    /// WireGuard static private key, stored as base64 string.
    pub private_key_base64: String,
    /// The virtual subnet for the P2P LAN.
    pub virtual_subnet: String,
    /// The port WireGuard listens on.
    pub listen_port: u16,
    /// The node's human-readable name.
    pub node_name: String,
    /// List of previously joined rooms.
    pub known_rooms: HashMap<String, KnownRoom>,
}

impl Default for ElysiumConfig {
    fn default() -> Self {
        let node_name = std::env::var("COMPUTERNAME")
            .unwrap_or_else(|_| "ElysiumNode".to_string());

        // Generate 32 bytes from cryptographically secure random number generator
        let key_bytes: [u8; 32] = rand::rng().random();
        let secret = StaticSecret::from(key_bytes);
        let private_key_base64 = base64_std.encode(secret.to_bytes());

        Self {
            private_key_base64,
            virtual_subnet: "10.7.0.0/24".to_string(),
            listen_port: 51820,
            node_name,
            known_rooms: HashMap::new(),
        }
    }
}

#[cfg(windows)]
mod dpapi {
    use std::ptr;
    use winapi::um::dpapi::{CryptProtectData, CryptUnprotectData};
    use winapi::um::wincrypt::DATA_BLOB;
    use winapi::um::winbase::LocalFree;
    
    pub fn encrypt(data: &str) -> Option<String> {
        use base64::Engine;
        let mut data_in = DATA_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut _,
        };
        let mut data_out = DATA_BLOB { cbData: 0, pbData: ptr::null_mut() };
        
        unsafe {
            let res = CryptProtectData(
                &mut data_in,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut data_out,
            );
            if res != 0 && !data_out.pbData.is_null() {
                let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
                let b64 = base64::engine::general_purpose::STANDARD.encode(slice);
                LocalFree(data_out.pbData as *mut _);
                Some(b64)
            } else {
                None
            }
        }
    }

    pub fn decrypt(b64: &str) -> Option<String> {
        use base64::Engine;
        let decoded = match base64::engine::general_purpose::STANDARD.decode(b64) {
            Ok(d) => d,
            Err(_) => return None,
        };
        
        let mut data_in = DATA_BLOB {
            cbData: decoded.len() as u32,
            pbData: decoded.as_ptr() as *mut _,
        };
        let mut data_out = DATA_BLOB { cbData: 0, pbData: ptr::null_mut() };
        
        unsafe {
            let res = CryptUnprotectData(
                &mut data_in,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut data_out,
            );
            if res != 0 && !data_out.pbData.is_null() {
                let slice = std::slice::from_raw_parts(data_out.pbData, data_out.cbData as usize);
                let string = String::from_utf8(slice.to_vec()).ok();
                LocalFree(data_out.pbData as *mut _);
                string
            } else {
                None
            }
        }
    }
}

impl ElysiumConfig {
    /// Get the path to the configuration file.
    fn get_config_path() -> Result<PathBuf> {
        let mut path = dirs::data_dir().context("Could not find AppData directory")?;
        path.push("Elysium");
        path.push("config.toml");
        Ok(path)
    }

    /// Load the configuration from disk, or create a new one if it doesn't exist.
    pub fn load_or_create() -> Result<Self> {
        let config_path = Self::get_config_path()?;
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)
                .context("Failed to read config file")?;
            let mut config: ElysiumConfig = toml::from_str(&content)
                .context("Failed to parse config file")?;
            
            #[cfg(windows)]
            if config.private_key_base64.starts_with("dpapi:") {
                let encrypted_b64 = config.private_key_base64.strip_prefix("dpapi:").unwrap();
                if let Some(decrypted) = dpapi::decrypt(encrypted_b64) {
                    config.private_key_base64 = decrypted;
                } else {
                    anyhow::bail!("Failed to decrypt DPAPI private key");
                }
            } else {
                info!("Plaintext private key detected, it will be encrypted on next save.");
                let c2 = config.clone();
                let _ = c2.save(); // Opportunistically encrypt it on disk
            }
            
            // Validate keypair integrity on load
            config.get_keypair().context("Corrupted private key in config")?;
            
            info!("Loaded configuration from {:?}", config_path);
            Ok(config)
        } else {
            warn!("Configuration not found, generating a new one at {:?}", config_path);
            let config = ElysiumConfig::default();
            config.save()?;
            Ok(config)
        }
    }

    /// Save the current configuration to disk.
    pub fn save(&self) -> Result<()> {
        let config_path = Self::get_config_path()?;
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).context("Failed to create config directory")?;
        }
        
        let mut to_save = self.clone();
        
        #[cfg(windows)]
        if let Some(encrypted) = dpapi::encrypt(&to_save.private_key_base64) {
            to_save.private_key_base64 = format!("dpapi:{}", encrypted);
        }
        
        let content = toml::to_string_pretty(&to_save)
            .context("Failed to serialize configuration")?;
        fs::write(&config_path, content)
            .context("Failed to write config file")?;
        info!("Saved configuration to {:?}", config_path);
        Ok(())
    }

    /// Get the WireGuard StaticSecret (private key) from the configuration.
    pub fn get_keypair(&self) -> Result<StaticSecret> {
        let decoded = base64_std.decode(&self.private_key_base64)
            .context("Failed to decode base64 private key")?;
        if decoded.len() != 32 {
            anyhow::bail!("Invalid private key length: expected 32 bytes, got {}", decoded.len());
        }
        if decoded.iter().all(|&b| b == 0) {
            anyhow::bail!("Invalid private key: all bytes are zero");
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&decoded);
        Ok(StaticSecret::from(bytes))
    }

    /// Get the WireGuard public key associated with this configuration, base64 encoded.
    pub fn get_public_key_base64(&self) -> Result<String> {
        let secret = self.get_keypair()?;
        let public_key = PublicKey::from(&secret);
        Ok(base64_std.encode(public_key.as_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_keypair_validity() {
        let cfg = ElysiumConfig::default();
        let keypair = cfg.get_keypair();
        assert!(keypair.is_ok());

        let pubkey = cfg.get_public_key_base64();
        assert!(pubkey.is_ok());
        let pubkey_str = pubkey.unwrap();
        assert_eq!(base64_std.decode(pubkey_str).unwrap().len(), 32);
    }

    #[test]
    fn test_invalid_key_detection() {
        let mut cfg = ElysiumConfig::default();
        cfg.private_key_base64 = "invalid-base64".to_string();
        assert!(cfg.get_keypair().is_err());

        // Test all zeros
        cfg.private_key_base64 = base64_std.encode([0u8; 32]);
        assert!(cfg.get_keypair().is_err());
    }
}
