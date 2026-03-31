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

pub struct MeetProvider {
    pub meet_url: String,
    pub cookie: Option<String>,
    client: Client,
}

impl MeetProvider {
    pub fn new(meet_url: impl Into<String>, cookie: Option<String>) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));

        if let Some(ref c) = cookie {
            headers.insert(COOKIE, HeaderValue::from_str(c)?);
        }

        let client = Client::builder().default_headers(headers).build()?;

        Ok(Self {
            meet_url: meet_url.into(),
            cookie,
            client,
        })
    }
}

#[async_trait]
impl CredentialProvider for MeetProvider {
    fn name(&self) -> &'static str {
        "Google Meet"
    }

    async fn obtain(&self) -> anyhow::Result<TurnCredentials> {
        tracing::info!(url = %self.meet_url, "fetching Google Meet page");

        let body = self.client.get(&self.meet_url).send().await?.text().await?;

        // ── strategy 1: iceServers array in page source ─────────────
        if let Some(creds) = try_ice_servers(&body)? {
            return Ok(creds);
        }

        // ── strategy 2: transport API response embedded in page ─────
        if let Some(creds) = try_turn_transport_api(&body)? {
            return Ok(creds);
        }

        // ── strategy 3: raw turn: URI + credential pairs ────────────
        if let Some(creds) = try_raw_turn_creds(&body)? {
            return Ok(creds);
        }

        // ── strategy 4: look for the TURN config API URL and fetch it
        if let Some(creds) = try_api_endpoint(&self.client, &body).await? {
            return Ok(creds);
        }

        if body.contains("accounts.google.com") || body.contains("ServiceLogin") {
            anyhow::bail!(
                "TURN credentials not found — Google may require authentication. \
                 Pass your session cookie with --cookie."
            );
        }

        anyhow::bail!("TURN credentials not found in Google Meet page")
    }
}

// ─── extraction strategies ──────────────────────────────────────────────────

fn try_ice_servers(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(r#"(?si)"iceServers"\s*:\s*(\[.*?\])\s*[,\}]"#)?;

    if let Some(caps) = re.captures(body) {
        let json = caps.get(1).unwrap().as_str();
        tracing::debug!("found iceServers array in Meet page");
        match crate::sdp::parse_ice_servers(json) {
            Ok(c) => return Ok(Some(c)),
            Err(e) => tracing::debug!("iceServers parse failed: {e}"),
        }
    }
    Ok(None)
}

fn try_turn_transport_api(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    // Match a JSON object containing a TURN url, username, and credential
    let re = Regex::new(
        r#""(turns?://[^"]+)"[^}]*?"username"\s*:\s*"([^"]+)"[^}]*?"credential"\s*:\s*"([^"]+)""#,
    )?;

    // Also try the non-// variant: turn:host:port?transport=...
    let re2 = Regex::new(
        r#""(turns?:[^"]+)"[^}]*?"username"\s*:\s*"([^"]+)"[^}]*?"credential"\s*:\s*"([^"]+)""#,
    )?;

    for regex in [&re, &re2] {
        if let Some(caps) = regex.captures(body) {
            let url = caps.get(1).unwrap().as_str();
            let username = caps.get(2).unwrap().as_str().to_string();
            let password = caps.get(3).unwrap().as_str().to_string();

            tracing::debug!(url, "found TURN transport entry in Meet page");

            let (host, port, _tls) = crate::sdp::parse_turn_uri(url)?;
            let addr = resolve(&host, port)?;

            return Ok(Some(TurnCredentials {
                server_addr: addr,
                username,
                password,
                realm: None,
            }));
        }
    }
    Ok(None)
}

fn try_raw_turn_creds(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re_url = Regex::new(r#""(turns?:(?://)?[^"]+)""#)?;
    let re_user = Regex::new(r#""username"\s*:\s*"([^"]+)""#)?;
    let re_cred = Regex::new(r#""credential"\s*:\s*"([^"]+)""#)?;

    if let Some(url_cap) = re_url.captures(body) {
        let url = url_cap.get(1).unwrap().as_str();

        if let (Some(user_cap), Some(cred_cap)) = (re_user.captures(body), re_cred.captures(body)) {
            let username = user_cap.get(1).unwrap().as_str().to_string();
            let password = cred_cap.get(1).unwrap().as_str().to_string();

            tracing::debug!(url, "found raw TURN URI + credentials in Meet page");

            let (host, port, _tls) = crate::sdp::parse_turn_uri(url)?;
            let addr = resolve(&host, port)?;

            return Ok(Some(TurnCredentials {
                server_addr: addr,
                username,
                password,
                realm: None,
            }));
        }
    }
    Ok(None)
}

async fn try_api_endpoint(client: &Client, body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(
        r#"(https://[a-zA-Z0-9._-]+\.google\.com/[^\s"']*(?:ice|turn|oLocation|oLocationProvide)[^\s"']*)"#,
    )?;

    for cap in re.captures_iter(body) {
        let api_url = cap.get(1).unwrap().as_str();
        tracing::debug!(url = api_url, "trying Meet API endpoint");

        match client.get(api_url).send().await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    if let Some(creds) = try_ice_servers(&text)? {
                        return Ok(Some(creds));
                    }
                    if let Some(creds) = try_turn_transport_api(&text)? {
                        return Ok(Some(creds));
                    }
                }
            }
            Err(e) => tracing::debug!("API fetch failed: {e}"),
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
        window.__CONFIG__ = {
            "iceServers": [
                {"urls": "stun:stun.l.google.com:19302"},
                {"urls": "turn:127.0.0.1:19305?transport=udp", "username": "meetuser", "credential": "meetpass"}
            ],
            "more": "stuff"
        };
        </script>
    "#;

    const PAGE_TRANSPORT: &str = r#"
        <script>
        var cfg = {
            servers: [
                {"url": "turn:127.0.0.1:19305?transport=udp", "username": "tuser", "credential": "tpass"}
            ]
        };
        </script>
    "#;

    const PAGE_RAW: &str = r#"
        <script>
        var x = "turn:127.0.0.1:19305?transport=udp";
        var u = {"username": "rawuser", "credential": "rawpass"};
        </script>
    "#;

    const PAGE_LOGIN: &str = r#"
        <html><body>
        <a href="https://accounts.google.com/ServiceLogin">Sign in</a>
        </body></html>
    "#;

    #[test]
    fn strategy1_ice_servers() {
        let creds = try_ice_servers(PAGE_ICE).unwrap().unwrap();
        assert_eq!(creds.username, "meetuser");
        assert_eq!(creds.password, "meetpass");
        assert_eq!(creds.server_addr.port(), 19305);
    }

    #[test]
    fn strategy2_transport_api() {
        let creds = try_turn_transport_api(PAGE_TRANSPORT).unwrap().unwrap();
        assert_eq!(creds.username, "tuser");
        assert_eq!(creds.password, "tpass");
    }

    #[test]
    fn strategy3_raw_turn() {
        let creds = try_raw_turn_creds(PAGE_RAW).unwrap().unwrap();
        assert_eq!(creds.username, "rawuser");
        assert_eq!(creds.password, "rawpass");
    }

    #[test]
    fn no_creds_returns_none() {
        assert!(try_ice_servers(PAGE_LOGIN).unwrap().is_none());
        assert!(try_turn_transport_api(PAGE_LOGIN).unwrap().is_none());
        assert!(try_raw_turn_creds(PAGE_LOGIN).unwrap().is_none());
    }

    #[test]
    fn embedded_ipv4_with_query() {
        let page = r#"{"urls":"turn:74.125.250.129:19305?transport=udp","username":"CK123","credential":"abc/def=="}"#;
        let creds = try_turn_transport_api(page).unwrap().unwrap();
        assert_eq!(creds.server_addr.port(), 19305);
        assert_eq!(creds.username, "CK123");
        assert!(creds.password.contains('/'));
    }
}
