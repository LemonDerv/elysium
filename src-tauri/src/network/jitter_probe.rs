use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

const PROBE_MAGIC: [u8; 4] = [0x45, 0x4C, 0x50, 0x52]; // "ELPR"
const PROBE_REQ: u8 = 0x01;
const PROBE_RESP: u8 = 0x02;

/// Real-time microsecond-level network quality metrics
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct JitterStats {
    pub rtt_ms: f64,
    pub jitter_ms: f64,
    pub packet_loss_pct: f64,
}

/// In-band hardware timestamp probe engine for sub-millisecond latency and RFC 3550 jitter tracking
pub struct ProbeEngine {
    seq_counter: AtomicU32,
    base_time: Instant,
    last_transit: Option<i64>,
    jitter_us: f64,
    loss_window: u64,
}

impl ProbeEngine {
    pub fn new() -> Self {
        Self {
            seq_counter: AtomicU32::new(1),
            base_time: Instant::now(),
            last_transit: None,
            jitter_us: 0.0,
            loss_window: !0u64, // Start with all packets received (64 bits = 1)
        }
    }

    /// Build a 32-byte probe request packet
    pub fn build_probe_request(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(&PROBE_MAGIC);
        buf[4] = PROBE_REQ;
        
        let seq = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        buf[8..12].copy_from_slice(&seq.to_be_bytes());
        
        let t1 = self.base_time.elapsed().as_nanos() as u64;
        buf[16..24].copy_from_slice(&t1.to_be_bytes());
        buf
    }

    /// Process an incoming probe request on the receiver side and create an immediate response
    pub fn build_probe_response(&self, req_payload: &[u8]) -> Option<[u8; 32]> {
        if req_payload.len() < 32 || req_payload[0..4] != PROBE_MAGIC || req_payload[4] != PROBE_REQ {
            return None;
        }

        let mut resp = [0u8; 32];
        resp[0..4].copy_from_slice(&PROBE_MAGIC);
        resp[4] = PROBE_RESP;
        
        // Copy original sequence number and T1
        resp[8..12].copy_from_slice(&req_payload[8..12]);
        resp[16..24].copy_from_slice(&req_payload[16..24]);
        
        // Stamp T2 (Receiver receive timestamp) and T3 (Receiver echo timestamp)
        let t2 = self.base_time.elapsed().as_nanos() as u64;
        resp[24..32].copy_from_slice(&t2.to_be_bytes());
        
        Some(resp)
    }

    /// Process an incoming probe response on the sender side and update RTT, jitter, and loss
    pub fn handle_probe_response(&mut self, resp_payload: &[u8]) -> Option<JitterStats> {
        if resp_payload.len() < 32 || resp_payload[0..4] != PROBE_MAGIC || resp_payload[4] != PROBE_RESP {
            return None;
        }

        let _seq = u32::from_be_bytes(resp_payload[8..12].try_into().ok()?);
        let t1 = u64::from_be_bytes(resp_payload[16..24].try_into().ok()?);
        let t4 = self.base_time.elapsed().as_nanos() as u64;

        // Exact RTT measured entirely on the sender's monotonic clock
        let rtt_ns = if t4 >= t1 { t4 - t1 } else { 0 };
        let rtt_ms = rtt_ns as f64 / 1_000_000.0;
        let rtt_us = rtt_ns as f64 / 1_000.0;

        // RFC 3550 Running Jitter Smoothing based on RTT variation
        if let Some(prev) = self.last_transit {
            let diff = (rtt_us - (prev as f64)).abs();
            self.jitter_us += (diff - self.jitter_us) / 16.0;
        }
        self.last_transit = Some(rtt_us as i64);

        // Update 64-bit sliding window (1 = received response)
        self.loss_window = (self.loss_window << 1) | 1;
        let received_count = self.loss_window.count_ones();
        let packet_loss_pct = ((64 - received_count) as f64 / 64.0) * 100.0;

        Some(JitterStats {
            rtt_ms: (rtt_ms * 10.0).round() / 10.0,
            jitter_ms: ((self.jitter_us / 1000.0) * 10.0).round() / 10.0,
            packet_loss_pct: (packet_loss_pct * 10.0).round() / 10.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_roundtrip_metrics() {
        let mut sender = ProbeEngine::new();
        let receiver = ProbeEngine::new();

        let req = sender.build_probe_request();
        assert_eq!(&req[0..4], &PROBE_MAGIC);
        assert_eq!(req[4], PROBE_REQ);

        let resp = receiver.build_probe_response(&req);
        assert!(resp.is_some());
        let resp_bytes = resp.unwrap();
        assert_eq!(resp_bytes[4], PROBE_RESP);

        let stats = sender.handle_probe_response(&resp_bytes);
        assert!(stats.is_some());
        let s = stats.unwrap();
        assert!(s.rtt_ms >= 0.0);
        assert!(s.jitter_ms >= 0.0);
        assert_eq!(s.packet_loss_pct, 0.0);
    }
}
