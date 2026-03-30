use std::net::{SocketAddr, ToSocketAddrs};

use async_trait::async_trait;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, COOKIE, USER_AGENT};
use reqwest::Client;
use turnnel_session::session::TurnCredentials;

use crate::CredentialProvider;

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                   AppleWebKit/537.36 (KHTML, like Gecko) \
                   Chrome/120.0.0.0 Safari/537.36";

pub struct VkProvider {
    pub invite_url: String,
    pub cookie: Option<String>,
    client: Client,
}

impl VkProvider {
    pub fn new(invite_url: impl Into<String>, cookie: Option<String>) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));

        if let Some(ref c) = cookie {
            headers.insert(COOKIE, HeaderValue::from_str(c)?);
        }

        let client = Client::builder().default_headers(headers).build()?;

        Ok(Self {
            invite_url: invite_url.into(),
            cookie,
            client,
        })
    }
}

#[async_trait]
impl CredentialProvider for VkProvider {
    fn name(&self) -> &'static str {
        "VK Calls"
    }

    async fn obtain(&self) -> anyhow::Result<TurnCredentials> {
        tracing::info!(url = %self.invite_url, "fetching VK call page");

        let body = self
            .client
            .get(&self.invite_url)
            .send()
            .await?
            .text()
            .await?;

        // ── strategy 1: standard iceServers JSON array ──────────────
        if let Some(creds) = try_ice_servers_array(&body)? {
            return Ok(creds);
        }

        // ── strategy 2: standalone TURN object ──────────────────────
        if let Some(creds) = try_turn_object(&body)? {
            return Ok(creds);
        }

        // ── strategy 3: wrap any TURN-bearing fragment into an array ─
        if let Some(creds) = try_turn_fragment(&body)? {
            return Ok(creds);
        }

        // ── nothing found ───────────────────────────────────────────
        if body.contains("login") || body.contains("Login") || body.contains("al_login") {
            anyhow::bail!(
                "TURN credentials not found — VK likely requires authorisation. \
                 Pass your session cookie with --cookie."
            );
        }

        anyhow::bail!("TURN credentials not found in VK page")
    }
}

// ─── extraction helpers ─────────────────────────────────────────────────────

fn try_ice_servers_array(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(r#"(?si)"iceServers"\s*:\s*(\[.*?\])\s*[,\}]"#)?;

    if let Some(caps) = re.captures(body) {
        let json = caps.get(1).unwrap().as_str();
        tracing::debug!("found iceServers array in VK response");
        match crate::sdp::parse_ice_servers(json) {
            Ok(c) => return Ok(Some(c)),
            Err(e) => tracing::debug!("iceServers parse failed: {e}"),
        }
    }
    Ok(None)
}

fn try_turn_object(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(
        r#"\{[^{]*?"urls?"\s*:\s*(?:\[\s*)?"(turns?:[^"]+)"(?:[\s\]]*)[^{]*?"username"\s*:\s*"([^"]+)"[^{]*?"credential"\s*:\s*"([^"]+)"[^\}]*\}"#,
    )?;

    if let Some(caps) = re.captures(body) {
        let url = caps.get(1).unwrap().as_str();
        let username = caps.get(2).unwrap().as_str().to_string();
        let password = caps.get(3).unwrap().as_str().to_string();

        tracing::debug!(url, "found raw TURN object in VK response");

        let (host, port, _tls) = crate::sdp::parse_turn_uri(url)?;
        let addr = resolve(&host, port)?;

        return Ok(Some(TurnCredentials {
            server_addr: addr,
            username,
            password,
            realm: None,
        }));
    }
    Ok(None)
}

fn try_turn_fragment(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(r#"(\{\s*"urls?"\s*:\s*\[?\s*"turns?:[^\]\}]+?\})"#)?;

    for cap in re.captures_iter(body) {
        let fragment = cap.get(1).unwrap().as_str();
        let fake_array = format!("[{fragment}]");

        match crate::sdp::parse_ice_servers(&fake_array) {
            Ok(c) => return Ok(Some(c)),
            Err(e) => tracing::trace!("fragment parse failed: {e}"),
        }
    }
    Ok(None)
}

fn resolve(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    let addr_str = format!("{host}:{port}");
    addr_str
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_ICE: &str = r#"
        <script>
        var config = {
            "iceServers": [
                {"urls":"stun:stun.vk.com:19302"},
                {"urls":"turn:127.0.0.1:3478","username":"vkuser","credential":"vkpass"}
            ],
            "other": true
        };
        </script>
    "#;

    const PAGE_OBJ: &str = r#"
        <script>
        initCall({"url":"turn:127.0.0.1:3478","username":"u2","credential":"p2"});
        </script>
    "#;

    const PAGE_LOGIN: &str = r#"
        <html><body>
        <div id="login">Please log in</div>
        </body></html>
    "#;

    #[test]
    fn strategy1_ice_servers() {
        let creds = try_ice_servers_array(PAGE_ICE).unwrap().unwrap();
        assert_eq!(creds.username, "vkuser");
        assert_eq!(creds.password, "vkpass");
        assert_eq!(creds.server_addr.port(), 3478);
    }

    #[test]
    fn strategy2_turn_object() {
        let creds = try_turn_object(PAGE_OBJ).unwrap().unwrap();
        assert_eq!(creds.username, "u2");
        assert_eq!(creds.password, "p2");
    }

    #[test]
    fn no_creds_returns_none() {
        assert!(try_ice_servers_array(PAGE_LOGIN).unwrap().is_none());
        assert!(try_turn_object(PAGE_LOGIN).unwrap().is_none());
        assert!(try_turn_fragment(PAGE_LOGIN).unwrap().is_none());
    }
}
