# Threat Model

This document outlines the threat model for Elysium.

## Boundaries

- **Authentication Boundary:** WireGuard static public/private key pairs verify peer identity.
- **Authorization Boundary:** Possession of the room code implies authorization to join.
- **Virtual LAN Boundary:** The `10.7.0.0/24` subnet. Only traffic matching this subnet is accepted from peers.
- **Physical LAN Boundary:** Separation between the virtual TUN adapter and the host's physical network adapters.
- **Frontend/Backend IPC Boundary:** Communication between the Tauri web frontend and the Rust backend.

## Trust Assumptions

### Trusted
- Local OS
- Local Elysium backend
- Cryptographic primitives (WireGuard / x25519)
- Configured identity

### Untrusted
- Internet peers
- Malicious peers within a room
- Malformed network packets
- Signaling/discovery data
- External STUN responses
- Compromised peer machines

## Security Properties

- **Confirmed Properties:**
  - Control-plane input limits: Implemented on node name (max 64 characters) and JSON message size (max 4KB limit in discovery).
  - Malformed packet handling: Cryptokey routing drops spoofed packets from peers.

- **Design Assumptions:**
  - WireGuard keys securely authenticate peers.

- **Configuration-Dependent Behavior:**
  - Virtual LAN functionality depends on secure host configurations and unmodified executables.
