//! Salamander-backed `quinn::AsyncUdpSocket`.
//!
//! Wire format (per datagram): salt(8) || XOR(payload, BLAKE2b-256(password||salt))
//!
//! When `dest` is set, datagrams that fail deobfuscation are UDP-forwarded to the
//! real destination (probe fallback). Successfully decoded datagrams go to Quinn.

use crate::salamander::{Salamander, SALT_LENGTH};
use quinn::{
    AsyncUdpSocket, ClientConfig, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, ToSocketAddrs};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

/// Shared state for dest fallback relay (peer ↔ real site).
struct DestRelay {
    dest: SocketAddr,
    /// peer -> last activity; simple 1:1 relay via same socket (we send from our listen port)
    peers: Mutex<HashMap<SocketAddr, SocketAddr>>,
}

pub struct SalamanderSocket {
    socket: UdpSocket,
    codec: Salamander,
    /// Scratch buffer for wire-format datagrams
    recv_buf: Mutex<Vec<u8>>,
    dest: Option<Arc<DestRelay>>,
}

impl fmt::Debug for SalamanderSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderSocket")
            .field("local", &self.socket.local_addr().ok())
            .field("dest_fallback", &self.dest.is_some())
            .finish()
    }
}

impl SalamanderSocket {
    pub async fn bind(
        addr: SocketAddr,
        password: &str,
        dest: Option<&str>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let codec = Salamander::new(password.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let dest = match dest {
            Some(d) if !d.is_empty() => {
                let dest_addr = d
                    .to_socket_addrs()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "cannot resolve dest")
                    })?;
                debug!("dest fallback target: {}", dest_addr);
                Some(Arc::new(DestRelay {
                    dest: dest_addr,
                    peers: Mutex::new(HashMap::new()),
                }))
            }
            _ => None,
        };
        Ok(Self {
            socket,
            codec,
            recv_buf: Mutex::new(vec![0u8; 65535]),
            dest,
        })
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(SalamanderPoller { socket: self })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let wire = self.codec.obfuscate(transmit.contents);
        match self.socket.try_send_to(&wire, transmit.destination) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => Err(e),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut guard = self
            .recv_buf
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        loop {
            let mut read_buf = ReadBuf::new(&mut guard[..]);
            let peer = match self.socket.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(addr)) => addr,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            let filled = read_buf.filled();

            // Dest fallback: packets that are not valid Salamander frames are
            // treated as probes and UDP-forwarded to the real site.
            match self.codec.deobfuscate(filled) {
                Ok(plain) => {
                    let len = plain.len().min(bufs[0].len());
                    bufs[0][..len].copy_from_slice(&plain[..len]);
                    meta[0] = RecvMeta {
                        addr: peer,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Err(_) => {
                    if let Some(relay) = &self.dest {
                        // Forward probe packet to real dest; map replies by tracking peer.
                        if let Ok(n) = self.socket.try_send_to(filled, relay.dest) {
                            trace!("dest-fallback forward {} bytes {} → {}", n, peer, relay.dest);
                            if let Ok(mut peers) = relay.peers.lock() {
                                peers.insert(peer, relay.dest);
                                // also mark reverse: if packet came FROM dest, send to last peer
                                // (simple: only one active probe peer)
                                peers.insert(relay.dest, peer);
                            }
                        }
                        // If packet is from dest (reply), forward to recorded peer
                        if peer == relay.dest {
                            if let Ok(peers) = relay.peers.lock() {
                                if let Some(client) = peers.get(&relay.dest).copied() {
                                    let _ = self.socket.try_send_to(filled, client);
                                }
                            }
                        }
                    }
                    // Do not deliver undecodable packets to Quinn — continue reading
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

struct SalamanderPoller {
    socket: Arc<SalamanderSocket>,
}

impl fmt::Debug for SalamanderPoller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SalamanderPoller").finish()
    }
}

impl UdpPoller for SalamanderPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.socket.socket.poll_send_ready(cx)
    }
}

// ---------------------------------------------------------------------------
// Endpoint factories
// ---------------------------------------------------------------------------

pub async fn create_server_endpoint(
    addr: SocketAddr,
    server_config: ServerConfig,
    salamander_password: Option<&str>,
    dest: Option<&str>,
) -> anyhow::Result<Endpoint> {
    if let Some(pw) = salamander_password {
        let sock = SalamanderSocket::bind(addr, pw, dest).await?;
        let ep = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            Arc::new(sock),
            Arc::new(TokioRuntime),
        )?;
        Ok(ep)
    } else {
        if dest.is_some() {
            warn!("dest fallback is most effective together with salamander obfuscation");
        }
        Ok(Endpoint::server(server_config, addr)?)
    }
}

pub async fn create_client_endpoint(
    salamander_password: Option<&str>,
    client_config: ClientConfig,
) -> anyhow::Result<Endpoint> {
    if let Some(pw) = salamander_password {
        let sock = SalamanderSocket::bind("0.0.0.0:0".parse()?, pw, None).await?;
        let mut ep = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            Arc::new(sock),
            Arc::new(TokioRuntime),
        )?;
        ep.set_default_client_config(client_config);
        Ok(ep)
    } else {
        let mut ep = Endpoint::client("0.0.0.0:0".parse()?)?;
        ep.set_default_client_config(client_config);
        Ok(ep)
    }
}

// silence unused import warning if SALT_LENGTH only used in docs
#[allow(dead_code)]
fn _salt_len() -> usize {
    SALT_LENGTH
}
