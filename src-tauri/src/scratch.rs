use std::sync::Arc;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::x25519::{StaticSecret, PublicKey};
use boringtun::noise::Tunn;

fn main() {
    let secret = StaticSecret::from([0u8; 32]);
    let pub_key = PublicKey::from(&secret);
    
    // Check RateLimiter::new
    let rl = RateLimiter::new(&pub_key, 100);
    
    let t = Tunn::new(
        secret,
        pub_key,
        None,
        None,
        0,
        Some(Arc::new(rl))
    );
    println!("Compiled!");
}
