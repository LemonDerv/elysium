# Security Architecture

## Identity Model
Nodes are identified by their WireGuard static public key. The relationship between the public and private key is based on the x25519 curve.

## Virtual IP Assignment
The host assigns virtual IPv4 addresses within the `10.7.0.0/24` subnet when a peer joins the room.

## Cryptokey Routing & Allowed IPs
Incoming UDP packets from a peer are decapsulated. The source IPv4 address of the inner packet must strictly match the peer's assigned virtual IP. Spoofed packets are dropped.

## Lateral Movement Prevention
The destination IPv4 address of incoming packets is verified to ensure it falls within the `10.7.0.0/24` virtual subnet. Packets destined for the host's external network are dropped.

## Packet Validation & Parsers
- WireGuard packet processing is handled by the `boringtun` crate. Third-party dependency security (like `boringtun`) is handled through dependency auditing, upstream advisories, and integration tests.
- We perform fuzzing and security testing on **Elysium-controlled parsers and integration boundaries**, rather than attempting to fuzz or fix vulnerabilities inside third-party dependencies directly.
- IPv6 packets are strictly dropped (IPv4 policy only).
- Discovery payloads (JSON) are size-limited to 4KB before parsing to prevent memory exhaustion.
- The `node_name` field is limited to 64 characters to prevent UI/resource abuse.

## Tauri Capabilities
The Tauri backend minimizes its capabilities. The `wintun.dll` loading process uses a safe path resolution fallback to prevent DLL hijacking via PATH modification.
