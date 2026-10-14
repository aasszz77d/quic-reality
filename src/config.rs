use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub mode: Mode,
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub server: String,
    pub reality: RealityConfig,
    #[serde(default)]
    pub local: LocalConfig,
    #[serde(default)]
    pub obfuscation: ObfuscationConfig,
    #[serde(default)]
    pub quic: QuicConfig,
    #[serde(default)]
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Server,
    Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealityConfig {
    #[serde(default)]
    pub private_key: String,
    #[serde(default)]
    pub public_key: String,
    pub short_id: String,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    /// Fallback real website for failed probes (host:port). Server only.
    #[serde(default)]
    pub dest: String,
}

fn default_server_name() -> String {
    "www.cloudflare.com".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalConfig {
    #[serde(default = "default_socks")]
    pub socks: String,
    /// HTTP CONNECT proxy listen address
    #[serde(default = "default_http")]
    pub http: String,
}

fn default_socks() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_http() -> String {
    "127.0.0.1:8080".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObfuscationConfig {
    /// "salamander" or empty/none
    #[serde(default)]
    pub type_: String,
    #[serde(default, rename = "type")]
    pub type_field: String,
    #[serde(default)]
    pub password: String,
}

impl ObfuscationConfig {
    pub fn kind(&self) -> &str {
        if !self.type_field.is_empty() {
            &self.type_field
        } else {
            &self.type_
        }
    }

    pub fn is_salamander(&self) -> bool {
        self.kind().eq_ignore_ascii_case("salamander") && !self.password.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// Enable Chrome-like transport parameter profile (simplified)
    #[serde(default = "default_true")]
    pub chrome_parrot: bool,
}

fn default_true() -> bool {
    true
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self { chrome_parrot: true }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::Server,
            listen: "0.0.0.0:443".to_string(),
            server: String::new(),
            reality: RealityConfig {
                private_key: String::new(),
                public_key: String::new(),
                short_id: "0123456789abcdef".to_string(),
                server_name: default_server_name(),
                dest: String::new(),
            },
            local: LocalConfig::default(),
            obfuscation: ObfuscationConfig::default(),
            quic: QuicConfig::default(),
            log_level: "info".to_string(),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&content)?;
        Ok(cfg)
    }

    pub fn example_server() -> String {
        r#"mode = "server"
listen = "0.0.0.0:8443"
log_level = "info"

[reality]
# cargo run -- keygen
private_key = "REPLACE_PRIVATE_KEY_HEX"
short_id = "0123456789abcdef"
server_name = "www.cloudflare.com"
# Failed probes are UDP-forwarded to this real site
dest = "www.cloudflare.com:443"

[obfuscation]
type = "salamander"
password = "change-me-salamander-password"

[quic]
chrome_parrot = true
"#
        .to_string()
    }

    pub fn example_client(public_key: &str, server: &str) -> String {
        format!(
            r#"mode = "client"
server = "{server}"
log_level = "info"

[reality]
public_key = "{public_key}"
short_id = "0123456789abcdef"
server_name = "www.cloudflare.com"

[local]
socks = "127.0.0.1:1080"
http = "127.0.0.1:8080"

[obfuscation]
type = "salamander"
password = "change-me-salamander-password"

[quic]
chrome_parrot = true
"#
        )
    }
}
