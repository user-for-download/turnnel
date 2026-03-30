use std::net::{SocketAddr, ToSocketAddrs};

use serde::Deserialize;
use turnnel_session::session::TurnCredentials;

#[derive(Debug, Deserialize)]
struct IceServer {
    #[serde(alias = "url")]
    urls: UrlsField,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    credential: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum UrlsField {
    Single(String),
    Multiple(Vec<String>),
}

impl UrlsField {
    fn into_vec(self) -> Vec<String> {
        match self {
            UrlsField::Single(s) => vec![s],
            UrlsField::Multiple(v) => v,
        }
    }
}

/// Parse a standard WebRTC `iceServers` JSON array and extract the first
/// TURN entry as [`TurnCredentials`].
///
/// Handles both `"urls"` and legacy `"url"` keys, and both string and
/// array-of-string values.
pub fn parse_ice_servers(json: &str) -> anyhow::Result<TurnCredentials> {
    let servers: Vec<IceServer> = serde_json::from_str(json)?;

    for server in servers {
        let username = server.username.unwrap_or_default();
        let credential = server.credential.unwrap_or_default();
        let urls = server.urls.into_vec();

        for raw_url in &urls {
            if !raw_url.starts_with("turn:") && !raw_url.starts_with("turns:") {
                continue;
            }

            let (host, port, _tls) = parse_turn_uri(raw_url)?;
            let addr = resolve(&host, port)?;

            return Ok(TurnCredentials {
                server_addr: addr,
                username,
                password: credential,
                realm: None,
            });
        }
    }

    anyhow::bail!("no TURN server found in iceServers array")
}

/// Extract `(host, port, is_tls)` from a TURN URI.
///
/// Accepted shapes:
/// - `turn:host:port`
/// - `turn://host:port`
/// - `turns:host:port?transport=tcp`
/// - `turn:host` (defaults to 3478 / 5349)
pub fn parse_turn_uri(uri: &str) -> anyhow::Result<(String, u16, bool)> {
    let (scheme, rest) = uri
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid TURN URI: {uri}"))?;

    let is_tls = scheme == "turns";
    let default_port: u16 = if is_tls { 5349 } else { 3478 };

    // strip optional "//"
    let rest = rest.strip_prefix("//").unwrap_or(rest);

    // strip query string (?transport=tcp etc.)
    let rest = rest.split('?').next().unwrap_or(rest);

    if let Some((host, port_str)) = rest.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(default_port);
        Ok((host.to_string(), port, is_tls))
    } else {
        Ok((rest.to_string(), default_port, is_tls))
    }
}

/// Resolve `host:port` to a [`SocketAddr`] via the OS resolver.
pub fn resolve(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let addr_str = format!("{host}:{port}");
    addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_basic() {
        let (h, p, tls) = parse_turn_uri("turn:example.com:3478").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 3478);
        assert!(!tls);
    }

    #[test]
    fn uri_default_port() {
        let (h, p, tls) = parse_turn_uri("turns:relay.vk.com").unwrap();
        assert_eq!(h, "relay.vk.com");
        assert_eq!(p, 5349);
        assert!(tls);
    }

    #[test]
    fn uri_with_query() {
        let (h, p, _) = parse_turn_uri("turn:relay.example.com:443?transport=tcp").unwrap();
        assert_eq!(h, "relay.example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn uri_double_slash() {
        let (h, p, _) = parse_turn_uri("turn://10.0.0.1:3478").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 3478);
    }

    #[test]
    fn ice_single_url() {
        let json = r#"[{
            "urls": "turn:127.0.0.1:3478",
            "username": "u",
            "credential": "p"
        }]"#;
        let c = parse_ice_servers(json).unwrap();
        assert_eq!(c.username, "u");
        assert_eq!(c.password, "p");
        assert_eq!(c.server_addr.port(), 3478);
    }

    #[test]
    fn ice_url_array() {
        let json = r#"[{
            "urls": ["stun:stun.example.com", "turn:127.0.0.1:3478"],
            "username": "bob",
            "credential": "secret"
        }]"#;
        let c = parse_ice_servers(json).unwrap();
        assert_eq!(c.username, "bob");
    }

    #[test]
    fn ice_legacy_url_field() {
        let json = r#"[{"url":"turn:127.0.0.1:3478","username":"a","credential":"b"}]"#;
        let c = parse_ice_servers(json).unwrap();
        assert_eq!(c.username, "a");
    }

    #[test]
    fn ice_stun_only_fails() {
        let json = r#"[{"urls":"stun:stun.l.google.com:19302"}]"#;
        assert!(parse_ice_servers(json).is_err());
    }
}
