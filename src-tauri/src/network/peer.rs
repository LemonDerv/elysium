use anyhow::Result;
use iroh::endpoint::{presets, Connection};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tracing::{error, info};

pub const ALPN: &[u8] = b"elysium/lan/1";

/// Manages P2P connections using iroh
pub struct PeerManager {
    pub endpoint: Endpoint,
}

impl PeerManager {
    /// Initialize iroh endpoint
    pub async fn init() -> Result<Self> {
        info!("Initializing iroh endpoint with gaming transport tuning");
        let mut builder = iroh::endpoint::QuicTransportConfig::builder()
            .keep_alive_interval(std::time::Duration::from_secs(1))
            .default_path_keep_alive_interval(std::time::Duration::from_secs(1))
            .datagram_receive_buffer_size(Some(2 * 1024 * 1024))
            .datagram_send_buffer_size(2 * 1024 * 1024);
        if let Ok(timeout) = std::time::Duration::from_secs(60).try_into() {
            builder = builder.max_idle_timeout(Some(timeout));
        }
        let transport_config = builder.build();

        let endpoint = Endpoint::builder(presets::N0)
            .transport_config(transport_config)
            .bind()
            .await?;
        endpoint.set_alpns(vec![ALPN.to_vec()]);
        Ok(Self { endpoint })
    }

    /// Return this node's iroh EndpointId
    pub fn get_node_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Get our endpoint address (includes relay & direct IP candidates)
    pub fn get_addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// Connect to a peer
    pub async fn connect_to_peer(&self, addr: EndpointAddr, alpn: &[u8]) -> Result<Connection> {
        info!("Connecting to peer: {}", addr.id);
        let conn = self.endpoint.connect(addr, alpn).await?;
        Ok(conn)
    }

    /// Listen for incoming peer connections
    pub async fn accept_connections(&self, _alpn: &[u8]) -> Result<()> {
        info!("Listening for peer connections");
        let ep = self.endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                match incoming.accept() {
                    Ok(accepting) => match accepting.await {
                        Ok(conn) => {
                            let remote_id = conn.remote_id();
                            info!("Accepted connection from {}", remote_id);
                        }
                        Err(e) => error!("Failed to establish accepted connection: {}", e),
                    },
                    Err(e) => error!("Failed to accept incoming: {}", e),
                }
            }
        });
        Ok(())
    }

    /// Send data over a QUIC stream
    pub async fn send_message(conn: &Connection, msg: &[u8]) -> Result<()> {
        let (mut send, _) = conn.open_bi().await?;
        send.write_all(msg).await?;
        send.finish()?;
        Ok(())
    }

    /// Receive data from a QUIC stream with a strict size limit
    pub async fn recv_message(conn: &Connection, max_len: usize) -> Result<Vec<u8>> {
        let (_, mut recv) = conn.accept_bi().await?;
        let msg = recv.read_to_end(max_len).await?;
        Ok(msg)
    }
}
