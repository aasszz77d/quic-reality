//! TLS + simplified Chrome QUIC profile for quinn 0.11 / rustls 0.23.

use anyhow::{Context, Result};
use quinn::{ClientConfig, ServerConfig, TransportConfig, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use std::time::Duration;

pub fn make_server_config(chrome_parrot: bool) -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .context("generate self-signed cert")?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .context("build rustls server config")?;
    // Chrome typically negotiates h3
    server_crypto.alpn_protocols = vec![b"h3".to_vec(), b"quic-reality".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("quic server crypto")?,
    ));
    *Arc::get_mut(&mut server_config.transport).unwrap() = make_transport(chrome_parrot);
    Ok(server_config)
}

pub fn make_client_config(_server_name: &str, chrome_parrot: bool) -> Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec(), b"quic-reality".to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("quic client crypto")?,
    ));
    client_config.transport_config(Arc::new(make_transport(chrome_parrot)));
    Ok(client_config)
}

/// Simplified Chrome-like transport parameters (values observed in Chrome QUIC).
/// Full wire-format parrot requires vendored quinn-proto; this sets compatible limits.
fn make_transport(chrome_parrot: bool) -> TransportConfig {
    let mut t = TransportConfig::default();
    if chrome_parrot {
        // Values aligned with Chrome / hysteria chrome profile defaults
        t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
        t.stream_receive_window(VarInt::from_u32(6_291_456)); // ~6MB
        t.receive_window(VarInt::from_u32(15_728_640));
        t.send_window(15_728_640);
        t.max_concurrent_bidi_streams(VarInt::from_u32(100));
        t.max_concurrent_uni_streams(VarInt::from_u32(100));
        t.ack_frequency_config(None);
        t.mtu_discovery_config(None);
    } else {
        t.max_concurrent_bidi_streams(VarInt::from_u32(1024));
        t.max_concurrent_uni_streams(VarInt::from_u32(1024));
    }
    t
}

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
