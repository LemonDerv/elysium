use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{StaticSecret, PublicKey};
use std::time::Instant;

fn main() {
    let server_secret = StaticSecret::from([1u8; 32]);
    let server_pub = PublicKey::from(&server_secret);
    
    let client_secret = StaticSecret::from([2u8; 32]);
    let client_pub = PublicKey::from(&client_secret);
    
    let mut server_tunn = Tunn::new(server_secret.clone(), client_pub, None, None, 0, None);
    
    let mut successes = 0;
    
    let start = Instant::now();
    let iterations = 1000;
    let mut out = vec![0u8; 1024];
    
    for i in 0..iterations {
        // Generate a NEW client Tunn each time to force a unique timestamp and ephemeral key
        let mut client_tunn = Tunn::new(client_secret.clone(), server_pub, None, None, i, None);
        let mut init_packet = vec![0u8; 1024];
        let TunnResult::WriteToNetwork(packet) = client_tunn.format_handshake_initiation(&mut init_packet, false) else {
            panic!("Failed to format initiation");
        };
        let valid_packet = packet.to_vec();
        
        match server_tunn.decapsulate(None, &valid_packet, &mut out) {
            TunnResult::WriteToNetwork(_) => successes += 1,
            _ => {},
        }
    }
    let elapsed = start.elapsed();
    
    let time_per_handshake = elapsed.as_secs_f64() / (iterations as f64);
    
    println!("Processed {} UNIQUE handshakes in {:?}", iterations, elapsed);
    println!("Successes: {}", successes);
    println!("Max handshakes per second (single core): {:.0}", 1.0 / time_per_handshake);
}
