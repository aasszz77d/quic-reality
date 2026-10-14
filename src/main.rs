mod auth;
mod client;
mod config;
mod protocol;
mod salamander;
mod obfs_socket;
mod server;
mod tls;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use config::{Config, Mode};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "quic-reality", about = "QUIC + Reality stealth proxy v0.2")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    Keygen,
    Example {
        #[arg(long)]
        client: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => {
            let kp = auth::KeyPair::generate();
            println!("private_key = \"{}\"", kp.private_hex());
            println!("public_key  = \"{}\"", kp.public_hex());
        }
        Commands::Example { client } => {
            if client {
                println!("{}", Config::example_client("YOUR_PUBLIC_KEY_HEX", "YOUR_SERVER:8443"));
            } else {
                println!("{}", Config::example_server());
            }
        }
        Commands::Run { config } => {
            let cfg = Config::load(&config)?;
            let filter = EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));
            tracing_subscriber::fmt().with_env_filter(filter).init();
            match cfg.mode {
                Mode::Server => {
                    if cfg.reality.private_key.is_empty() {
                        bail!("server needs reality.private_key");
                    }
                    info!("quic-reality server v0.2");
                    server::run(cfg).await?;
                }
                Mode::Client => {
                    if cfg.reality.public_key.is_empty() || cfg.server.is_empty() {
                        bail!("client needs public_key and server");
                    }
                    info!("quic-reality client v0.2");
                    client::run(cfg).await?;
                }
            }
        }
    }
    Ok(())
}
