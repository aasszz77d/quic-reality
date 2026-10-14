use crate::auth::{AuthRequest, AUTH_OK};
use crate::config::Config;
use crate::obfs_socket::create_client_endpoint;
use crate::protocol::{
    encode_request, encode_udp_packet, CMD_TCP, CMD_UDP, STATUS_OK, TargetAddr,
};
use crate::salamander::Salamander;
use crate::tls::make_client_config;
use anyhow::{bail, Context, Result};
use bytes::{BufMut, BytesMut};
use quinn::{Connection, RecvStream, SendStream};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

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
    let http_addr: SocketAddr = cfg.local.http.parse().context("http")?;
    let chrome = cfg.quic.chrome_parrot;
    let pw = if cfg.obfuscation.is_salamander() {
        let codec = Salamander::new(cfg.obfuscation.password.as_bytes())
            .map_err(|e| anyhow::anyhow!("salamander: {e}"))?;
        let probe = codec.obfuscate(b"quic-reality");
        let _ = codec
            .deobfuscate(&probe)
            .map_err(|e| anyhow::anyhow!("salamander self-test: {e}"))?;
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

    // SOCKS5 TCP + UDP
    let socks_listener = TcpListener::bind(socks_addr).await?;
    info!("SOCKS5 on {}", socks_addr);

    // Dedicated UDP socket for SOCKS5 UDP ASSOCIATE (same host, ephemeral or same port attempt)
    let udp_sock = Arc::new(UdpSocket::bind(SocketAddr::new(socks_addr.ip(), 0)).await?);
    let udp_bind = udp_sock.local_addr()?;
    info!("SOCKS5 UDP on {}", udp_bind);

    // HTTP CONNECT proxy
    let http_listener = TcpListener::bind(http_addr).await?;
    info!("HTTP proxy on {}", http_addr);

    let conn_s = Arc::clone(&conn);
    let udp_s = Arc::clone(&udp_sock);
    tokio::spawn(async move {
        loop {
            match socks_listener.accept().await {
                Ok((tcp, peer)) => {
                    let conn = Arc::clone(&conn_s);
                    let udp = Arc::clone(&udp_s);
                    let udp_bind = udp_bind;
                    tokio::spawn(async move {
                        if let Err(e) = handle_socks(tcp, peer, conn, udp, udp_bind).await {
                            debug!("socks {}: {}", peer, e);
                        }
                    });
                }
                Err(e) => warn!("socks accept: {}", e),
            }
        }
    });

    // SOCKS5 UDP data plane: local clients send SOCKS5-UDP datagrams here
    let conn_u = Arc::clone(&conn);
    let udp_u = Arc::clone(&udp_sock);
    tokio::spawn(async move {
        if let Err(e) = socks_udp_loop(udp_u, conn_u).await {
            debug!("socks udp loop: {}", e);
        }
    });

    // HTTP proxy accept loop (main task)
    loop {
        let (tcp, peer) = http_listener.accept().await?;
        let conn = Arc::clone(&conn);
        tokio::spawn(async move {
            if let Err(e) = handle_http(tcp, peer, conn).await {
                debug!("http {}: {}", peer, e);
            }
        });
    }
}

fn resolve(addr: &str) -> Result<SocketAddr> {
    addr.to_socket_addrs()?.next().context("resolve")
}

// ---------------------------------------------------------------------------
// SOCKS5
// ---------------------------------------------------------------------------

async fn handle_socks(
    mut tcp: TcpStream,
    peer: SocketAddr,
    conn: Arc<Connection>,
    _udp: Arc<UdpSocket>,
    udp_bind: SocketAddr,
) -> Result<()> {
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
            // CONNECT
            debug!("{:?} TCP → {:?}", peer, target);
            let (mut qs, mut qr) = conn.open_bi().await?;
            qs.write_all(&encode_request(CMD_TCP, &target)).await?;
            let mut st = [0u8; 1];
            if qr.read(&mut st).await?.unwrap_or(0) != 1 || st[0] != STATUS_OK {
                tcp.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                bail!("remote fail");
            }
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            relay_tcp(tcp, qs, qr).await
        }
        0x03 => {
            // UDP ASSOCIATE — reply with our UDP bind address
            debug!("{:?} UDP ASSOCIATE → notify {}", peer, udp_bind);
            let (mut qs, mut qr) = conn.open_bi().await?;
            let dummy = TargetAddr::Ip("0.0.0.0:0".parse()?);
            qs.write_all(&encode_request(CMD_UDP, &dummy)).await?;
            let mut st = [0u8; 1];
            if qr.read(&mut st).await?.unwrap_or(0) != 1 || st[0] != STATUS_OK {
                tcp.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                bail!("udp assoc fail");
            }
            // Reply BND.ADDR = udp_bind so client sends UDP there
            let mut reply = vec![0x05, 0x00, 0x00];
            match udp_bind {
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

            // Hold the association stream; UDP data goes via socks_udp_loop.
            // Keep QR stream open for server→client UDP frames.
            let conn2 = Arc::clone(&conn);
            tokio::spawn(async move {
                if let Err(e) = drain_udp_associate(qs, qr, conn2).await {
                    debug!("udp assoc drain: {}", e);
                }
            });

            // TCP control connection stays open until client closes
            let mut b = [0u8; 32];
            while tcp.read(&mut b).await.unwrap_or(0) > 0 {}
            Ok(())
        }
        _ => {
            tcp.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("unsupported cmd")
        }
    }
}

/// Server pushes framed UDP packets on the associate stream; we need a path back to local clients.
/// For simplicity, associate streams only open the server-side relay; local SOCKS UDP
/// uses a separate QUIC stream per datagram batch via socks_udp_loop.
async fn drain_udp_associate(
    mut _qs: SendStream,
    mut qr: RecvStream,
    _conn: Arc<Connection>,
) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match qr.read(&mut buf).await? {
            Some(0) | None => break,
            Some(_) => {
                // Server→client UDP on associate stream is optional;
                // primary path is per-datagram streams from socks_udp_loop.
            }
        }
    }
    Ok(())
}

/// SOCKS5 UDP header:
///   RSV(2)=0 | FRAG(1)=0 | ATYP | DST.ADDR | DST.PORT | DATA
async fn socks_udp_loop(udp: Arc<UdpSocket>, conn: Arc<Connection>) -> Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    // Track client addresses for replies
    loop {
        let (n, client) = udp.recv_from(&mut buf).await?;
        if n < 4 {
            continue;
        }
        // Parse SOCKS5 UDP request
        if buf[2] != 0 {
            continue; // FRAG not supported
        }
        let target = match parse_socks_addr(&buf[3..n]) {
            Ok(t) => t,
            Err(_) => continue,
        };
        // payload starts after address
        let header_len = socks_addr_len(&buf[3..n]).unwrap_or(0);
        if 3 + header_len > n {
            continue;
        }
        let payload = &buf[3 + header_len..n];

        let conn = Arc::clone(&conn);
        let udp = Arc::clone(&udp);
        let payload = payload.to_vec();
        tokio::spawn(async move {
            if let Err(e) = udp_exchange(conn, udp, client, target, payload).await {
                debug!("udp exchange: {}", e);
            }
        });
    }
}

async fn udp_exchange(
    conn: Arc<Connection>,
    udp: Arc<UdpSocket>,
    client: SocketAddr,
    target: TargetAddr,
    payload: Vec<u8>,
) -> Result<()> {
    let (mut qs, mut qr) = conn.open_bi().await?;
    // Open UDP associate-style stream with first target, then send framed packet
    qs.write_all(&encode_request(CMD_UDP, &target)).await?;
    let mut st = [0u8; 1];
    if qr.read(&mut st).await?.unwrap_or(0) != 1 || st[0] != STATUS_OK {
        bail!("udp open fail");
    }
    let frame = encode_udp_packet(&target, &payload);
    qs.write_all(&frame).await?;
    let _ = qs.finish();

    // Read one framed response (best-effort for request/response UDP)
    let mut acc = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    // wait for at least length prefix
    while acc.len() < 2 {
        match qr.read(&mut buf).await? {
            Some(n) if n > 0 => acc.extend_from_slice(&buf[..n]),
            _ => return Ok(()),
        }
    }
    let len = u16::from_be_bytes([acc[0], acc[1]]) as usize;
    while acc.len() < 2 + len {
        match qr.read(&mut buf).await? {
            Some(n) if n > 0 => acc.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    if acc.len() >= 2 + len {
        let body = &acc[2..2 + len];
        // body = addr + payload; rebuild SOCKS5 UDP response to client
        if let Ok((addr, data)) = decode_frame_addr_payload(body) {
            let mut out = BytesMut::new();
            out.put_u16(0); // RSV
            out.put_u8(0); // FRAG
            encode_socks_addr(&addr, &mut out);
            out.extend_from_slice(&data);
            let _ = udp.send_to(&out, client).await;
        }
    }
    Ok(())
}

fn decode_frame_addr_payload(body: &[u8]) -> Result<(TargetAddr, Vec<u8>)> {
    let mut b = body;
    let addr = TargetAddr::decode(&mut b)?;
    Ok((addr, b.to_vec()))
}

fn encode_socks_addr(addr: &TargetAddr, out: &mut BytesMut) {
    match addr {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            out.put_u8(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.put_u16(a.port());
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            out.put_u8(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.put_u16(a.port());
        }
        TargetAddr::Domain(h, p) => {
            out.put_u8(0x03);
            let b = h.as_bytes();
            out.put_u8(b.len() as u8);
            out.extend_from_slice(b);
            out.put_u16(*p);
        }
    }
}

fn socks_addr_len(data: &[u8]) -> Option<usize> {
    if data.is_empty() {
        return None;
    }
    match data[0] {
        0x01 => Some(1 + 4 + 2),
        0x04 => Some(1 + 16 + 2),
        0x03 => {
            if data.len() < 2 {
                return None;
            }
            Some(1 + 1 + data[1] as usize + 2)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// HTTP CONNECT / absolute-URI proxy
// ---------------------------------------------------------------------------

async fn handle_http(mut tcp: TcpStream, peer: SocketAddr, conn: Arc<Connection>) -> Result<()> {
    // Read request line + headers into a buffer
    let mut header_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = tcp.read(&mut tmp).await?;
        if n == 0 {
            bail!("eof headers");
        }
        header_buf.extend_from_slice(&tmp[..n]);
        if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if header_buf.len() > 64 * 1024 {
            bail!("headers too large");
        }
    }
    let header_str = String::from_utf8_lossy(&header_buf);
    let mut lines = header_str.split("\r\n");
    let req_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        bail!("bad http req");
    }
    let method = parts[0].to_uppercase();
    let target_raw = parts[1].to_string();

    if method == "CONNECT" {
        // host:port
        let target = parse_host_port(&target_raw)?;
        debug!("{:?} HTTP CONNECT → {:?}", peer, target);
        let (mut qs, mut qr) = conn.open_bi().await?;
        qs.write_all(&encode_request(CMD_TCP, &target)).await?;
        let mut st = [0u8; 1];
        if qr.read(&mut st).await?.unwrap_or(0) != 1 || st[0] != STATUS_OK {
            let _ = tcp
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            bail!("connect fail");
        }
        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        relay_tcp(tcp, qs, qr).await
    } else {
        // Forward HTTP proxy absolute URL: GET http://host/path
        let (hostport, path) = split_absolute_url(&target_raw)?;
        let target = parse_host_port(&hostport)?;
        debug!("{:?} HTTP {} → {:?}", peer, method, target);
        let (mut qs, mut qr) = conn.open_bi().await?;
        qs.write_all(&encode_request(CMD_TCP, &target)).await?;
        let mut st = [0u8; 1];
        if qr.read(&mut st).await?.unwrap_or(0) != 1 || st[0] != STATUS_OK {
            let _ = tcp
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            bail!("connect fail");
        }
        // Rebuild request line with path only
        let new_req = format!("{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", method, path, hostport.split(':').next().unwrap_or(""));
        qs.write_all(new_req.as_bytes()).await?;
        relay_tcp(tcp, qs, qr).await
    }
}

fn parse_host_port(s: &str) -> Result<TargetAddr> {
    let s = s.trim();
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Ok(TargetAddr::Domain(h.to_string(), port));
        }
    }
    // default port 80
    Ok(TargetAddr::Domain(s.to_string(), 80))
}

fn split_absolute_url(url: &str) -> Result<(String, String)> {
    // http://host:port/path
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    if let Some(idx) = rest.find('/') {
        let hostport = &rest[..idx];
        let path = &rest[idx..];
        let hostport = if hostport.contains(':') {
            hostport.to_string()
        } else if url.starts_with("https://") {
            format!("{}:443", hostport)
        } else {
            format!("{}:80", hostport)
        };
        Ok((hostport, path.to_string()))
    } else {
        let hostport = if rest.contains(':') {
            rest.to_string()
        } else {
            format!("{}:80", rest)
        };
        Ok((hostport, "/".to_string()))
    }
}

async fn relay_tcp(tcp: TcpStream, mut qs: SendStream, mut qr: RecvStream) -> Result<()> {
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
