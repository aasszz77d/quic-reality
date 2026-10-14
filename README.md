# quic-reality v0.2

QUIC + Reality 风格隐蔽代理：hy2 速度 + Reality 隐蔽 + Salamander + UDP ASSOCIATE。

## 已实现

| 功能 | 状态 | 说明 |
|------|------|------|
| QUIC 传输 | ✅ | quinn 0.11 |
| Reality 认证 | ✅ | X25519 + shortId + HMAC 时间窗 |
| Chrome QUIC 指纹（简化） | ✅ | 传输参数对齐 Chrome 量级；完整 wire parrot 需 vendored quinn-proto |
| Salamander 混淆 | ✅ 模块 | 编解码完成；完整 UDP 层接入需自定义 AsyncUdpSocket（配置已预留） |
| dest 探测回落 | ✅ 框架 | 认证失败触发回落路径；完整透明 UDP 转发需 pre-QUIC 原始 socket |
| TCP 代理 | ✅ | SOCKS5 CONNECT |
| UDP ASSOCIATE | ✅ | 服务端完整 framing；客户端 SOCKS5 UDP 控制通道 |

## 快速开始

```bash
cargo run -- keygen
# 填入 examples/*.toml

cargo run --release -- run -c examples/server.toml
cargo run --release -- run -c examples/client.toml

curl --socks5-hostname 127.0.0.1:1080 https://www.cloudflare.com/cdn-cgi/trace
```

## 架构

```
SOCKS5 → Client → [Salamander?] → QUIC(Chrome profile) → Reality Auth → Server
                                                              ↓ fail
                                                         dest fallback
```

## 后续完整化方向

1. 自定义 `quinn::AsyncUdpSocket` 实现 Salamander 逐包混淆
2. 在 QUIC 握手前拦截 UDP，认证失败则整包转发 dest（真正 Reality 风格）
3. 从 hysteria-rust vendor 的 `chrome.rs` 移植完整 TransportParameters 编码
4. SOCKS5 UDP 数据面完整封装
