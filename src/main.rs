use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use turnnel_providers::CredentialProvider;
use turnnel_session::session::TurnCredentials;
use turnnel_session::transport::TransportProtocol;

#[derive(Parser)]
#[command(name = "turnnel", version, about = "TURN-based tunnel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the TURN client proxy
    Client {
        /// Credential provider: "manual", "yandex", "vk"
        #[arg(long, default_value = "manual")]
        provider: String,

        /// Call URL (required for yandex / vk providers)
        #[arg(long)]
        call_url: Option<String>,

        /// Browser cookie header for private calls (VK)
        #[arg(long)]
        cookie: Option<String>,

        /// TURN server address (required for "manual")
        #[arg(long)]
        turn_server: Option<SocketAddr>,

        /// TURN username (required for "manual")
        #[arg(long)]
        turn_user: Option<String>,

        /// TURN password (required for "manual")
        #[arg(long)]
        turn_pass: Option<String>,

        /// TURN realm override
        #[arg(long)]
        turn_realm: Option<String>,

        /// Peer (remote relay) address
        #[arg(long)]
        peer: SocketAddr,

        /// Local UDP listen address for WireGuard
        #[arg(long, default_value = "127.0.0.1:51820")]
        listen: SocketAddr,

        /// Use TCP transport to the TURN server
        #[arg(long, conflicts_with = "tls_sni")]
        tcp: bool,

        /// Use TLS transport with the given SNI
        #[arg(long, conflicts_with = "tcp")]
        tls_sni: Option<String>,
    },

    /// Run the peer-side UDP relay
    Peer {
        /// External listen address (TURN relay sends here)
        #[arg(long, default_value = "0.0.0.0:9999")]
        listen: SocketAddr,

        /// Forward to local WireGuard
        #[arg(long, default_value = "127.0.0.1:51820")]
        forward: SocketAddr,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Client {
            provider,
            call_url,
            cookie,
            turn_server,
            turn_user,
            turn_pass,
            turn_realm,
            peer,
            listen,
            tcp,
            tls_sni,
        } => {
            let protocol = if let Some(sni) = tls_sni {
                TransportProtocol::Tls { sni }
            } else if tcp {
                TransportProtocol::Tcp
            } else {
                TransportProtocol::Udp
            };

            tracing::info!(provider = %provider, "resolving TURN credentials");

            let credentials = match provider.as_str() {
                "manual" => TurnCredentials {
                    server_addr: turn_server
                        .expect("--turn-server is required for the manual provider"),
                    username: turn_user.expect("--turn-user is required for the manual provider"),
                    password: turn_pass.expect("--turn-pass is required for the manual provider"),
                    realm: turn_realm,
                },
                "yandex" => {
                    let url = call_url.expect("--call-url is required for the yandex provider");
                    let p = turnnel_providers::yandex::YandexProvider::new(url);
                    p.obtain().await?
                }
                "vk" => {
                    let url = call_url.expect("--call-url is required for the vk provider");
                    let p = turnnel_providers::vk::VkProvider::new(url, cookie)?;
                    p.obtain().await?
                }
                other => {
                    anyhow::bail!("unknown provider '{other}' — choose manual, yandex, or vk");
                }
            };

            tracing::info!(
                turn = %credentials.server_addr,
                user = %credentials.username,
                peer = %peer,
                listen = %listen,
                protocol = ?protocol,
                "starting client"
            );

            let config = turnnel_client::proxy::ProxyConfig {
                listen_addr: listen,
                credentials,
                peer_addr: peer,
                refresh_interval: Duration::from_secs(30),
                protocol,
            };

            turnnel_client::proxy::run(config).await?;
        }

        Command::Peer { listen, forward } => {
            tracing::info!(listen = %listen, forward = %forward, "starting peer relay");

            let config = turnnel_peer::relay::PeerConfig::new(listen, forward);
            turnnel_peer::relay::run(config).await?;
        }
    }

    Ok(())
}
