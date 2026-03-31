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
    /// Run as client (create TURN allocation, proxy local WireGuard traffic)
    Client {
        /// Credential provider
        #[arg(long, default_value = "manual")]
        provider: String,

        #[arg(long)]
        call_url: Option<String>,

        #[arg(long)]
        cookie: Option<String>,

        #[arg(long)]
        auth_token: Option<String>,

        #[arg(long)]
        turn_server: Option<SocketAddr>,

        #[arg(long)]
        turn_user: Option<String>,

        #[arg(long)]
        turn_pass: Option<String>,

        #[arg(long)]
        turn_realm: Option<String>,

        /// Public IP:port of the peer machine (must be routable from the TURN server)
        #[arg(long)]
        peer: SocketAddr,

        #[arg(long, default_value = "127.0.0.1:51820")]
        listen: SocketAddr,

        #[arg(long, conflicts_with = "tls_sni")]
        tcp: bool,

        #[arg(long, conflicts_with = "tcp")]
        tls_sni: Option<String>,

        /// Skip the check that --peer is a public IP
        #[arg(long)]
        allow_private_peer: bool,
    },

    /// Run as peer relay (forward TURN-relayed traffic to local WireGuard)
    Peer {
        /// Address to listen on for TURN-relayed packets
        #[arg(long, default_value = "0.0.0.0:9999")]
        listen: SocketAddr,

        /// Local WireGuard endpoint to forward to
        #[arg(long, default_value = "127.0.0.1:51820")]
        forward: SocketAddr,
    },
}

/// Check whether an IP is loopback, private, or link-local — addresses that
/// TURN servers will almost certainly reject with 403 Forbidden.
fn is_non_routable(addr: &SocketAddr) -> bool {
    use std::net::IpAddr;
    match addr.ip() {
        IpAddr::V4(ip) => {
            ip.is_loopback()          // 127.0.0.0/8
                || ip.is_private()    // 10/8, 172.16/12, 192.168/16
                || ip.is_link_local() // 169.254/16
                || ip.is_unspecified() // 0.0.0.0
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()          // ::1
                || ip.is_unspecified() // ::
                // unique-local fc00::/7
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (ip.segments()[0] & 0xffc0) == 0xfe80
        }
    }
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
            auth_token,
            turn_server,
            turn_user,
            turn_pass,
            turn_realm,
            peer,
            listen,
            tcp,
            tls_sni,
            allow_private_peer,
        } => {
            // ── Validate peer address ──────────────────────────────────
            if is_non_routable(&peer) && !allow_private_peer {
                anyhow::bail!(
                    "peer address {peer} is a loopback/private/link-local address.\n\
                     \n\
                     TURN servers reject permissions for non-routable IPs (RFC 5766 §17.2).\n\
                     The --peer flag must be the PUBLIC IP:port of the machine running `turnnel peer`.\n\
                     \n\
                     Example:\n\
                     \n\
                     # On peer machine (public IP 203.0.113.50):\n\
                     turnnel peer --listen 0.0.0.0:9999 --forward 127.0.0.1:51820\n\
                     \n\
                     # On client machine:\n\
                     turnnel client --peer 203.0.113.50:9999 ...\n\
                     \n\
                     If you really know what you're doing, pass --allow-private-peer to skip this check."
                );
            }

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
                    let p = if let Some(token) = auth_token {
                        turnnel_providers::vk::VkProvider::with_auth_token(url, cookie, token)?
                    } else {
                        turnnel_providers::vk::VkProvider::new(url, cookie)?
                    };
                    p.obtain().await?
                }
                "meet" => {
                    let url = call_url.expect("--call-url is required for the meet provider");
                    let p = turnnel_providers::meet::MeetProvider::new(url, cookie)?;
                    p.obtain().await?
                }
                "teams" => {
                    let url = call_url.expect("--call-url is required for the teams provider");
                    let p = turnnel_providers::teams::TeamsProvider::new(url, cookie)?;
                    p.obtain().await?
                }
                other => {
                    anyhow::bail!(
                        "unknown provider '{other}' — choose manual, yandex, vk, meet, or teams"
                    );
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
