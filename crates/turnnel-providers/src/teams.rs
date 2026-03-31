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

pub struct TeamsProvider {
    pub meet_url: String,
    pub cookie: Option<String>,
    client: Client,
}

impl TeamsProvider {
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
impl CredentialProvider for TeamsProvider {
    fn name(&self) -> &'static str {
        "Microsoft Teams"
    }

    async fn obtain(&self) -> anyhow::Result<TurnCredentials> {
        tracing::info!(url = %self.meet_url, "fetching Microsoft Teams page");

        let body = self.client.get(&self.meet_url).send().await?.text().await?;

        if let Some(creds) = try_ice_servers(&body)? {
            return Ok(creds);
        }

        if let Some(creds) = try_relay_config(&body)? {
            return Ok(creds);
        }

        if let Some(creds) = try_turn_object(&body)? {
            return Ok(creds);
        }

        if let Some(creds) = try_calling_service_api(&self.client, &body).await? {
            return Ok(creds);
        }

        if let Some(creds) = try_raw_turn_creds(&body)? {
            return Ok(creds);
        }

        if body.contains("login.microsoftonline.com")
            || body.contains("login.live.com")
            || body.contains("Sign in")
        {
            anyhow::bail!(
                "TURN credentials not found — Teams likely requires authentication. \
                 Pass your session cookie with --cookie."
            );
        }

        anyhow::bail!("TURN credentials not found in Microsoft Teams page")
    }
}

// ─── extraction strategies ──────────────────────────────────────────────────

fn try_ice_servers(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(r#"(?si)"iceServers"\s*:\s*(\[.*?\])\s*[,\}]"#)?;

    if let Some(caps) = re.captures(body) {
        let json = caps.get(1).unwrap().as_str();
        tracing::debug!("found iceServers array in Teams page");
        match crate::sdp::parse_ice_servers(json) {
            Ok(c) => return Ok(Some(c)),
            Err(e) => tracing::debug!("iceServers parse failed: {e}"),
        }
    }
    Ok(None)
}

fn try_relay_config(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    // Pattern 1: relayUrl + relayUsername + relayPassword
    let re_relay = Regex::new(
        r#"(?si)"relay(?:Turn)?Url"\s*:\s*"(turns?:(?://)?[^"]+)".*?"relay(?:Turn)?Username"\s*:\s*"([^"]+)".*?"relay(?:Turn)?(?:Password|Credential)"\s*:\s*"([^"]+)""#,
    )?;

    if let Some(caps) = re_relay.captures(body) {
        let url = caps.get(1).unwrap().as_str();
        let username = caps.get(2).unwrap().as_str().to_string();
        let password = caps.get(3).unwrap().as_str().to_string();

        tracing::debug!(url, "found Teams relay config (relayUrl pattern)");
        let (host, port, _tls) = crate::sdp::parse_turn_uri(url)?;
        let addr = resolve(&host, port)?;

        return Ok(Some(TurnCredentials {
            server_addr: addr,
            username,
            password,
            realm: None,
        }));
    }

    // Pattern 2: turnServerUrl + turnUsername + turnPassword
    let re_turn = Regex::new(
        r#"(?si)"turnServer(?:Url)?"\s*:\s*"(turns?:(?://)?[^"]+)".*?"turnUsername"\s*:\s*"([^"]+)".*?"turnPassword"\s*:\s*"([^"]+)""#,
    )?;

    if let Some(caps) = re_turn.captures(body) {
        let url = caps.get(1).unwrap().as_str();
        let username = caps.get(2).unwrap().as_str().to_string();
        let password = caps.get(3).unwrap().as_str().to_string();

        tracing::debug!(url, "found Teams relay config (turnServer pattern)");
        let (host, port, _tls) = crate::sdp::parse_turn_uri(url)?;
        let addr = resolve(&host, port)?;

        return Ok(Some(TurnCredentials {
            server_addr: addr,
            username,
            password,
            realm: None,
        }));
    }

    // Pattern 3: fqdn/hostname + port + username + password
    let re_fqdn = Regex::new(
        r#"(?si)"(?:fqdns?|hostname)"\s*:\s*\[?\s*"([^"]+)".*?"port"\s*:\s*(\d+).*?"username"\s*:\s*"([^"]+)".*?"(?:password|credential)"\s*:\s*"([^"]+)""#,
    )?;

    if let Some(caps) = re_fqdn.captures(body) {
        let host = caps.get(1).unwrap().as_str();
        let port: u16 = caps.get(2).unwrap().as_str().parse().unwrap_or(3478);
        let username = caps.get(3).unwrap().as_str().to_string();
        let password = caps.get(4).unwrap().as_str().to_string();

        tracing::debug!(host, port, "found Teams relay config (fqdn+port pattern)");
        let addr = resolve(host, port)?;

        return Ok(Some(TurnCredentials {
            server_addr: addr,
            username,
            password,
            realm: None,
        }));
    }

    Ok(None)
}

fn try_turn_object(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(
        r#"\{[^{]*?"urls?"\s*:\s*(?:\[\s*)?"(turns?:(?://)?[^"]+)"(?:[\s\]]*)[^{]*?"username"\s*:\s*"([^"]+)"[^{]*?"credential"\s*:\s*"([^"]+)"[^\}]*\}"#,
    )?;

    if let Some(caps) = re.captures(body) {
        let url = caps.get(1).unwrap().as_str();
        let username = caps.get(2).unwrap().as_str().to_string();
        let password = caps.get(3).unwrap().as_str().to_string();

        tracing::debug!(url, "found TURN object in Teams page");
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

async fn try_calling_service_api(
    client: &Client,
    body: &str,
) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(
        r#"(https://[a-zA-Z0-9._-]+\.(?:microsoft\.com|skype\.com|teams\.microsoft\.com|teams\.live\.com)/[^\s"']*(?:relay|turn|calling|trouter|config)[^\s"']*)"#,
    )?;

    for cap in re.captures_iter(body) {
        let api_url = cap.get(1).unwrap().as_str();
        tracing::debug!(url = api_url, "trying Teams API endpoint");

        match client.get(api_url).send().await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    if let Some(creds) = try_ice_servers(&text)? {
                        return Ok(Some(creds));
                    }
                    if let Some(creds) = try_relay_config(&text)? {
                        return Ok(Some(creds));
                    }
                    if let Some(creds) = try_turn_object(&text)? {
                        return Ok(Some(creds));
                    }
                }
            }
            Err(e) => tracing::debug!("API fetch failed: {e}"),
        }
    }
    Ok(None)
}

fn try_raw_turn_creds(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re_url = Regex::new(r#""(turns?:(?://)?[^"]+)""#)?;
    let re_user = Regex::new(r#""(?:username|turnUsername|relayUsername)"\s*:\s*"([^"]+)""#)?;
    let re_cred = Regex::new(
        r#""(?:credential|password|turnPassword|relayPassword|relayCredential)"\s*:\s*"([^"]+)""#,
    )?;

    if let Some(url_cap) = re_url.captures(body) {
        let url = url_cap.get(1).unwrap().as_str();

        if let (Some(user_cap), Some(cred_cap)) = (re_user.captures(body), re_cred.captures(body)) {
            let username = user_cap.get(1).unwrap().as_str().to_string();
            let password = cred_cap.get(1).unwrap().as_str().to_string();

            tracing::debug!(url, "found raw TURN URI + credentials in Teams page");
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
        var mediaConfig = {
            "iceServers": [
                {"urls": "stun:stun.teams.microsoft.com:19302"},
                {"urls": "turn:127.0.0.1:3478?transport=udp", "username": "teamsuser", "credential": "teamspass"}
            ],
            "iceTransportPolicy": "relay"
        };
        </script>
    "#;

    const PAGE_RELAY: &str = r#"
        <script>
        window.__config = {
            "relayUrl": "turn:127.0.0.1:3478?transport=tcp",
            "relayUsername": "relayU",
            "relayPassword": "relayP",
            "other": true
        };
        </script>
    "#;

    const PAGE_TURN_SERVER: &str = r#"
        <script>
        var cfg = {
            "turnServerUrl": "turns:127.0.0.1:443?transport=tcp",
            "turnUsername": "tsUser",
            "turnPassword": "tsPass"
        };
        </script>
    "#;

    const PAGE_FQDN: &str = r#"
        <script>
        var relay = {
            "turn": {
                "fqdns": ["127.0.0.1"],
                "port": 3478,
                "username": "fqdnUser",
                "password": "fqdnPass"
            }
        };
        </script>
    "#;

    const PAGE_TURN_OBJ: &str = r#"
        <script>
        initCall({"urls":"turn:127.0.0.1:3478","username":"objU","credential":"objP"});
        </script>
    "#;

    const PAGE_RAW: &str = r#"
        <script>
        var x = "turn:127.0.0.1:3478?transport=udp";
        var cfg = {"turnUsername": "rawU", "turnPassword": "rawP"};
        </script>
    "#;

    const PAGE_LOGIN: &str = r#"
        <html><body>
        <a href="https://login.microsoftonline.com/common/oauth2">Sign in</a>
        </body></html>
    "#;

    #[test]
    fn strategy1_ice_servers() {
        let creds = try_ice_servers(PAGE_ICE).unwrap().unwrap();
        assert_eq!(creds.username, "teamsuser");
        assert_eq!(creds.password, "teamspass");
        assert_eq!(creds.server_addr.port(), 3478);
    }

    #[test]
    fn strategy2_relay_config() {
        let creds = try_relay_config(PAGE_RELAY).unwrap().unwrap();
        assert_eq!(creds.username, "relayU");
        assert_eq!(creds.password, "relayP");
        assert_eq!(creds.server_addr.port(), 3478);
    }

    #[test]
    fn strategy2_turn_server_url() {
        let creds = try_relay_config(PAGE_TURN_SERVER).unwrap().unwrap();
        assert_eq!(creds.username, "tsUser");
        assert_eq!(creds.password, "tsPass");
        assert_eq!(creds.server_addr.port(), 443);
    }

    #[test]
    fn strategy2_fqdn_port() {
        let creds = try_relay_config(PAGE_FQDN).unwrap().unwrap();
        assert_eq!(creds.username, "fqdnUser");
        assert_eq!(creds.password, "fqdnPass");
        assert_eq!(creds.server_addr.port(), 3478);
    }

    #[test]
    fn strategy3_turn_object() {
        let creds = try_turn_object(PAGE_TURN_OBJ).unwrap().unwrap();
        assert_eq!(creds.username, "objU");
        assert_eq!(creds.password, "objP");
    }

    #[test]
    fn strategy5_raw_turn_creds() {
        let creds = try_raw_turn_creds(PAGE_RAW).unwrap().unwrap();
        assert_eq!(creds.username, "rawU");
        assert_eq!(creds.password, "rawP");
    }

    #[test]
    fn no_creds_returns_none() {
        assert!(try_ice_servers(PAGE_LOGIN).unwrap().is_none());
        assert!(try_relay_config(PAGE_LOGIN).unwrap().is_none());
        assert!(try_turn_object(PAGE_LOGIN).unwrap().is_none());
        assert!(try_raw_turn_creds(PAGE_LOGIN).unwrap().is_none());
    }

    #[test]
    fn relay_credential_variant() {
        let page = r#"{"relayTurnUrl":"turn:127.0.0.1:3478","relayTurnUsername":"u1","relayTurnCredential":"p1"}"#;
        let creds = try_relay_config(page).unwrap().unwrap();
        assert_eq!(creds.username, "u1");
        assert_eq!(creds.password, "p1");
    }
}
