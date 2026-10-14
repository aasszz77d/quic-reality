//! Reality-style authentication for quic-reality MVP.
//!
//! Simplified REALITY-like handshake:
//! - Server holds X25519 private key
//! - Client holds corresponding public key + short_id
//! - Client sends: short_id || timestamp || ephemeral_pub || signature
//! - Signature = HMAC-SHA256(shared_secret, short_id || timestamp || ephemeral_pub)
//!   where shared_secret is derived from (server_private, client_ephemeral) or
//!   simply HMAC with the static shared secret for MVP simplicity.
//!
//! For MVP we use a static shared secret derived from the keypair to keep
//! implementation simple while still requiring the correct key material.

use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

pub const AUTH_MAGIC: &[u8] = b"QR01"; // quic-reality v0.1
pub const SHORT_ID_MAX: usize = 16;
pub const TIMESTAMP_TOLERANCE_SECS: i64 = 120; // ±2 minutes

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private: StaticSecret,
    pub public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let private = StaticSecret::random_from_rng(&mut rng);
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    pub fn from_private_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex.trim()).context("invalid private key hex")?;
        if bytes.len() != 32 {
            bail!("private key must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let private = StaticSecret::from(arr);
        let public = PublicKey::from(&private);
        Ok(Self { private, public })
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.public.as_bytes())
    }

    pub fn private_hex(&self) -> String {
        hex::encode(self.private.to_bytes())
    }
}

/// Derive a static shared secret from the Reality key material.
/// In full Reality this would be dynamic; for MVP we use the public key bytes
/// as the HMAC key base (both sides can compute the same value when client
/// knows the public key and server knows the private→public).
fn shared_secret(public: &PublicKey) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(b"quic-reality-v1").expect("hmac");
    mac.update(public.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[derive(Debug)]
pub struct AuthRequest {
    pub short_id: Vec<u8>,
    pub timestamp: u64,
    pub nonce: [u8; 16],
    pub mac: [u8; 32],
}

impl AuthRequest {
    pub fn build(short_id: &[u8], public: &PublicKey) -> Result<Vec<u8>> {
        if short_id.len() > SHORT_ID_MAX {
            bail!("short_id too long");
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

        let secret = shared_secret(public);
        let mut mac = HmacSha256::new_from_slice(&secret)?;
        mac.update(AUTH_MAGIC);
        mac.update(short_id);
        mac.update(&timestamp.to_be_bytes());
        mac.update(&nonce);
        let tag = mac.finalize().into_bytes();

        let mut buf = Vec::with_capacity(4 + 1 + short_id.len() + 8 + 16 + 32);
        buf.extend_from_slice(AUTH_MAGIC);
        buf.push(short_id.len() as u8);
        buf.extend_from_slice(short_id);
        buf.extend_from_slice(&timestamp.to_be_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&tag);
        Ok(buf)
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 4 + 1 + 8 + 16 + 32 {
            bail!("auth packet too short");
        }
        if &data[0..4] != AUTH_MAGIC {
            bail!("invalid auth magic");
        }
        let sid_len = data[4] as usize;
        if sid_len > SHORT_ID_MAX || data.len() < 5 + sid_len + 8 + 16 + 32 {
            bail!("invalid short_id length");
        }
        let mut offset = 5;
        let short_id = data[offset..offset + sid_len].to_vec();
        offset += sid_len;
        let timestamp = u64::from_be_bytes(data[offset..offset + 8].try_into()?);
        offset += 8;
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&data[offset..offset + 16]);
        offset += 16;
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&data[offset..offset + 32]);
        Ok(Self {
            short_id,
            timestamp,
            nonce,
            mac,
        })
    }

    pub fn verify(&self, expected_short_id: &[u8], public: &PublicKey) -> Result<()> {
        // Check short_id
        if self.short_id != expected_short_id {
            bail!("short_id mismatch");
        }
        // Check timestamp window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;
        let ts = self.timestamp as i64;
        if (now - ts).abs() > TIMESTAMP_TOLERANCE_SECS {
            bail!("timestamp out of range");
        }
        // Verify MAC
        let secret = shared_secret(public);
        let mut mac = HmacSha256::new_from_slice(&secret)?;
        mac.update(AUTH_MAGIC);
        mac.update(&self.short_id);
        mac.update(&self.timestamp.to_be_bytes());
        mac.update(&self.nonce);
        mac.verify_slice(&self.mac)
            .map_err(|_| anyhow::anyhow!("auth MAC verification failed"))?;
        Ok(())
    }
}

/// Auth response: simple OK / FAIL
pub const AUTH_OK: u8 = 0x01;
pub const AUTH_FAIL: u8 = 0x00;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_roundtrip() {
        let kp = KeyPair::generate();
        let short_id = hex::decode("0123456789abcdef").unwrap();
        let packet = AuthRequest::build(&short_id, &kp.public).unwrap();
        let req = AuthRequest::parse(&packet).unwrap();
        req.verify(&short_id, &kp.public).unwrap();
    }
}
