//! Optional Salamander UDP wrapping.
//!
//! Full `AsyncUdpSocket` integration depends on exact quinn version APIs.
//! This module provides helpers; when salamander is enabled we currently
//! log and use the standard endpoint, while the Salamander codec itself
//! is fully implemented and unit-tested in `salamander.rs`.
//!
//! To complete wire-level obfuscation, implement `quinn::AsyncUdpSocket`
//! using `Salamander::{obfuscate,deobfuscate}` around `try_send`/`poll_recv`
//! (see hysteria-rust `obfs_socket.rs` for the reference pattern).

use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use tracing::info;

pub async fn create_server_endpoint(
    addr: SocketAddr,
    server_config: ServerConfig,
    salamander_password: Option<&str>,
) -> Result<Endpoint> {
    if salamander_password.is_some() {
        info!("salamander password set — codec ready; enable full AsyncUdpSocket for wire obfuscation");
    }
    Ok(Endpoint::server(server_config, addr)?)
}

pub async fn create_client_endpoint(
    salamander_password: Option<&str>,
    client_config: ClientConfig,
) -> Result<Endpoint> {
    if salamander_password.is_some() {
        info!("salamander password set — codec ready; enable full AsyncUdpSocket for wire obfuscation");
    }
    let mut ep = Endpoint::client("0.0.0.0:0".parse()?)?;
    ep.set_default_client_config(client_config);
    Ok(ep)
}
