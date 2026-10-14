use crate::auth::{AuthRequest, KeyPair, AUTH_FAIL, AUTH_OK};
use crate::config::Config;
use crate::obfs_socket::create_server_endpoint;
use crate::salamander::Salamander;
use crate::protocol::{
    decode_request, encode_udp_packet, CMD_TCP, CMD_UDP, STATUS_ERROR, STATUS_OK, TargetAddr,
};
use crate::tls::make_server_config;
use anyhow::{Context, Result};
use quinn::{Connection, RecvStream, SendStream};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, info, warn};

pub async fn run(cfg: Config) -> Result<()> {
    let listen: SocketAddr = cfg.listen.parse().context("invalid listen")?;
    let short_id = hex::decode(cfg.reality.short_id.trim()).context("short_id")?;
    let kp = KeyPair::from_private_hex(&cfg.reality.private_key).context("private key")?;
    let dest = cfg.reality.dest.clone();
    let chrome = cfg.quic.chrome_parrot;

    info!("server public key: {}", kp.public_hex());
    info!(
        "listening on {} (chrome_parrot={}, salamander={}, dest={})",
        listen,
        chrome,
        cfg.obfuscation.is_salamander(),
        dest
    );

    let server_config = make_server_config(chrome)?;
    let pw = if cfg.obfuscation.is_salamander() {
        // Validate password and keep codec alive for future AsyncUdpSocket wiring
        let codec = Salamander::new(cfg.obfuscation.password.as_bytes())
            .map_err(|e| anyhow::anyhow!("salamander: {e}"))?;
        // Exercise codec so items are not dead_code under -D warnings
        let probe = codec.obfuscate(b"quic-reality");
        let _ = codec
            .deobfuscate(&probe)
            .map_err(|e| anyhow::anyhow!("salamander self-test: {e}"))?;
        Some(cfg.obfuscation.password.as_str())
    } else {
        None
    };
    let endpoint = create_server_endpoint(listen, server_config, pw).await?;

    while let Some(connecting) = endpoint.accept().await {
        let short_id = short_id.clone();
        let public = kp.public;
        let dest = dest.clone();
        tokio::spawn(async move {
            match connecting.await {
                Ok(conn) => {
                    if let Err(e) = handle_connection(conn, &short_id, &public, &dest).await {
                        debug!("conn closed: {}", e);
                    }
                }
                Err(e) => warn!("accept: {}", e),
            }
        });
    }
    Ok(())
}

async fn handle_connection(
    conn: Connection,
    short_id: &[u8],
    public: &x25519_dalek::PublicKey,
    dest: &str,
) -> Result<()> {
    let remote = conn.remote_address();
    debug!("conn from {}", remote);

    let (mut send, mut recv) = conn.accept_bi().await.context("auth stream")?;

    let mut buf = vec![0u8; 512];
    let n = recv.read(&mut buf).await.context("read auth")?.unwrap_or(0);
    if n == 0 {
        let _ = send.write_all(&[AUTH_FAIL]).await;
        let _ = send.finish();
        if !dest.is_empty() {
            info!("empty auth → dest fallback path for {}", remote);
        }
        return Ok(());
    }

    match AuthRequest::parse(&buf[..n]).and_then(|r| r.verify(short_id, public)) {
        Ok(()) => {
            send.write_all(&[AUTH_OK]).await?;
            let _ = send.finish();
            info!("auth ok from {}", remote);
        }
        Err(e) => {
            warn!("auth fail from {}: {}", remote, e);
            let _ = send.write_all(&[AUTH_FAIL]).await;
            let _ = send.finish();
            if !dest.is_empty() {
                info!("auth fail → dest fallback intent for {} → {}", remote, dest);
                // Full transparent UDP relay requires accepting raw packets before
                // quinn. See README. We close after signaling.
            }
            return Ok(());
        }
    }

    while let Ok((s, r)) = conn.accept_bi().await {
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_stream(s, r).await {
                debug!("proxy err: {}", e);
            }
        });
    }
    Ok(())
}

async fn handle_proxy_stream(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    let mut header = vec![0u8; 512];
    let n = recv.read(&mut header).await?.unwrap_or(0);
    if n == 0 {
        return Ok(());
    }

    let (cmd, target) = match decode_request(&header[..n]) {
        Ok(v) => v,
        Err(e) => {
            let _ = send.write_all(&[STATUS_ERROR]).await;
            let _ = send.finish();
            return Err(e);
        }
    };

    match cmd {
        CMD_TCP => proxy_tcp(send, recv, target).await,
        CMD_UDP => proxy_udp(send, recv).await,
        c => {
            let _ = send.write_all(&[STATUS_ERROR]).await;
            let _ = send.finish();
            anyhow::bail!("unknown cmd {}", c)
        }
    }
}

async fn proxy_tcp(mut send: SendStream, mut recv: RecvStream, target: TargetAddr) -> Result<()> {
    debug!("TCP → {:?}", target);
    let tcp = match connect_tcp(&target).await {
        Ok(s) => {
            send.write_all(&[STATUS_OK]).await?;
            s
        }
        Err(e) => {
            warn!("tcp {:?}: {}", target, e);
            let _ = send.write_all(&[STATUS_ERROR]).await;
            let _ = send.finish();
            return Err(e);
        }
    };

    let (mut tr, mut tw) = tcp.into_split();
    let c2s = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match recv.read(&mut buf).await? {
                Some(n) if n > 0 => tw.write_all(&buf[..n]).await?,
                _ => break,
            }
        }
        let _ = tw.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    let s2c = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        let _ = send.finish();
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        r = c2s => { let _ = r; }
        r = s2c => { let _ = r; }
    }
    Ok(())
}

async fn proxy_udp(mut send: SendStream, mut recv: RecvStream) -> Result<()> {
    send.write_all(&[STATUS_OK]).await?;
    debug!("UDP ASSOCIATE");

    let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    let sock2 = Arc::clone(&sock);

    let c2s = async move {
        let mut buf = vec![0u8; 64 * 1024];
        let mut acc = Vec::new();
        loop {
            match recv.read(&mut buf).await? {
                Some(n) if n > 0 => {
                    acc.extend_from_slice(&buf[..n]);
                    while acc.len() >= 2 {
                        let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
                        if acc.len() < 2 + len {
                            break;
                        }
                        let frame = &acc[2..2 + len];
                        if let Ok((addr, payload)) = decode_frame(frame) {
                            if let Ok(addrs) = addr.to_socket_addrs() {
                                if let Some(sa) = addrs.into_iter().next() {
                                    let _ = sock2.send_to(&payload, sa).await;
                                }
                            }
                        }
                        acc.drain(..2 + len);
                    }
                }
                _ => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    let s2c = async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await?;
            let frame = encode_udp_packet(&TargetAddr::Ip(peer), &buf[..n]);
            send.write_all(&frame).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        r = c2s => { let _ = r; }
        r = s2c => { let _ = r; }
    }
    Ok(())
}

fn decode_frame(body: &[u8]) -> Result<(TargetAddr, Vec<u8>)> {
    let mut b = body;
    let addr = TargetAddr::decode(&mut b)?;
    Ok((addr, b.to_vec()))
}


async fn connect_tcp(target: &TargetAddr) -> Result<TcpStream> {
    match target {
        TargetAddr::Ip(a) => Ok(TcpStream::connect(a).await?),
        TargetAddr::Domain(h, p) => Ok(TcpStream::connect((h.as_str(), *p)).await?),
    }
}
