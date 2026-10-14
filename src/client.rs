use crate::auth::{AuthRequest, AUTH_OK};
use crate::config::Config;
use crate::obfs_socket::create_client_endpoint;
use crate::protocol::{encode_request, CMD_TCP, CMD_UDP, STATUS_OK, TargetAddr};
use crate::tls::make_client_config;
use anyhow::{bail, Context, Result};
use quinn::Connection;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info};

pub async fn run(cfg: Config) -> Result<()> {
    let server_addr: SocketAddr = resolve(&cfg.server)?;
    let short_id = hex::decode(cfg.reality.short_id.trim()).context("short_id")?;
    let public_bytes = hex::decode(cfg.reality.public_key.trim()).context("public_key")?;
    if public_bytes.len() != 32 {
        bail!("public_key must be 32 bytes");
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&public_bytes);
    let public = x25519_dalek::PublicKey::from(pk);

    let socks_addr: SocketAddr = cfg.local.socks.parse().context("socks")?;
    let chrome = cfg.quic.chrome_parrot;
    let pw = if cfg.obfuscation.is_salamander() {
        Some(cfg.obfuscation.password.as_str())
    } else {
        None
    };

    info!(
        "connecting to {} (chrome={}, salamander={})",
        server_addr,
        chrome,
        pw.is_some()
    );

    let client_config = make_client_config(&cfg.reality.server_name, chrome)?;
    let endpoint = create_client_endpoint(pw, client_config).await?;

    let conn = endpoint
        .connect(server_addr, &cfg.reality.server_name)?
        .await
        .context("QUIC connect")?;
    info!("QUIC connected");

    let (mut send, mut recv) = conn.open_bi().await?;
    let auth_pkt = AuthRequest::build(&short_id, &public)?;
    send.write_all(&auth_pkt).await?;
    let _ = send.finish();
    let mut resp = [0u8; 1];
    let n = recv.read(&mut resp).await?.unwrap_or(0);
    if n != 1 || resp[0] != AUTH_OK {
        bail!("auth rejected");
    }
    info!("authenticated");

    let conn = Arc::new(conn);
    let listener = TcpListener::bind(socks_addr).await?;
    info!("SOCKS5 on {}", socks_addr);

    loop {
        let (tcp, peer) = listener.accept().await?;
        let conn = Arc::clone(&conn);
        tokio::spawn(async move {
            if let Err(e) = handle_socks(tcp, peer, conn).await {
                debug!("socks {}: {}", peer, e);
            }
        });
    }
}

fn resolve(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()?.next().context("resolve")
}

async fn handle_socks(mut tcp: TcpStream, peer: SocketAddr, conn: Arc<Connection>) -> Result<()> {
    let mut buf = [0u8; 512];
    let n = tcp.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        bail!("not socks5");
    }
    tcp.write_all(&[0x05, 0x00]).await?;

    let n = tcp.read(&mut buf).await?;
    if n < 7 || buf[0] != 0x05 {
        bail!("bad req");
    }
    let cmd = buf[1];
    let target = parse_socks_addr(&buf[3..n])?;

    match cmd {
        0x01 => {
            debug!("{:?} TCP → {:?}", peer, target);
            let (mut qs, mut qr) = conn.open_bi().await?;
            qs.write_all(&encode_request(CMD_TCP, &target)).await?;
            let mut st = [0u8; 1];
            if qr.read(&mut st).await?.unwrap_or(0) != 1 || st[0] != STATUS_OK {
                tcp.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                bail!("remote fail");
            }
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            relay(tcp, qs, qr).await
        }
        0x03 => {
            debug!("{:?} UDP ASSOCIATE", peer);
            let (mut qs, mut qr) = conn.open_bi().await?;
            let dummy = TargetAddr::Ip("0.0.0.0:0".parse()?);
            qs.write_all(&encode_request(CMD_UDP, &dummy)).await?;
            let mut st = [0u8; 1];
            if qr.read(&mut st).await?.unwrap_or(0) != 1 || st[0] != STATUS_OK {
                tcp.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                bail!("udp assoc fail");
            }
            let local = tcp.local_addr().unwrap_or(peer);
            let mut reply = vec![0x05, 0x00, 0x00];
            match local {
                SocketAddr::V4(a) => {
                    reply.push(0x01);
                    reply.extend_from_slice(&a.ip().octets());
                    reply.extend_from_slice(&a.port().to_be_bytes());
                }
                SocketAddr::V6(a) => {
                    reply.push(0x04);
                    reply.extend_from_slice(&a.ip().octets());
                    reply.extend_from_slice(&a.port().to_be_bytes());
                }
            }
            tcp.write_all(&reply).await?;
            // Hold association until TCP closes
            let mut b = [0u8; 32];
            while tcp.read(&mut b).await.unwrap_or(0) > 0 {}
            let _ = (qs, qr);
            Ok(())
        }
        _ => {
            tcp.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            bail!("unsupported cmd")
        }
    }
}

async fn relay(tcp: TcpStream, mut qs: quinn::SendStream, mut qr: quinn::RecvStream) -> Result<()> {
    let (mut tr, mut tw) = tcp.into_split();
    let c2s = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = tr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            qs.write_all(&buf[..n]).await?;
        }
        let _ = qs.finish();
        Ok::<(), anyhow::Error>(())
    };
    let s2c = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match qr.read(&mut buf).await? {
                Some(n) if n > 0 => tw.write_all(&buf[..n]).await?,
                _ => break,
            }
        }
        let _ = tw.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        r = c2s => { let _ = r; }
        r = s2c => { let _ = r; }
    }
    Ok(())
}

fn parse_socks_addr(data: &[u8]) -> Result<TargetAddr> {
    if data.is_empty() {
        bail!("empty");
    }
    match data[0] {
        0x01 => {
            if data.len() < 7 {
                bail!("short v4");
            }
            let ip = std::net::Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Ok(TargetAddr::Ip(SocketAddr::new(ip.into(), port)))
        }
        0x03 => {
            let len = data[1] as usize;
            if data.len() < 2 + len + 2 {
                bail!("short domain");
            }
            let host = String::from_utf8(data[2..2 + len].to_vec())?;
            let port = u16::from_be_bytes([data[2 + len], data[3 + len]]);
            Ok(TargetAddr::Domain(host, port))
        }
        0x04 => {
            if data.len() < 19 {
                bail!("short v6");
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&data[1..17]);
            let port = u16::from_be_bytes([data[17], data[18]]);
            Ok(TargetAddr::Ip(SocketAddr::new(
                std::net::Ipv6Addr::from(ip).into(),
                port,
            )))
        }
        _ => bail!("bad atyp"),
    }
}
