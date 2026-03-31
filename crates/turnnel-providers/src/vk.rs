use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;

use async_trait::async_trait;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, COOKIE, ORIGIN, REFERER, USER_AGENT};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use turnnel_session::session::TurnCredentials;

use crate::CredentialProvider;

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                   AppleWebKit/537.36 (KHTML, like Gecko) \
                   Chrome/146.0.0.0 Safari/537.36";

/// OK (Odnoklassniki) federation API
const OK_FB_API: &str = "https://fb.do/api";
const OK_APP_KEY: &str = "CGMMEJLGDIHBABABA";

pub struct VkProvider {
    pub call_url: String,
    pub cookie: Option<String>,
    pub auth_token: Option<String>,
    client: Client,
}

impl VkProvider {
    pub fn new(call_url: impl Into<String>, cookie: Option<String>) -> anyhow::Result<Self> {
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));
        if let Some(ref c) = cookie {
            headers.insert(COOKIE, HeaderValue::from_str(c)?);
        }
        let client = Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()?;
        Ok(Self {
            call_url: call_url.into(),
            cookie,
            auth_token: None,
            client,
        })
    }

    pub fn with_auth_token(
        call_url: impl Into<String>,
        cookie: Option<String>,
        auth_token: String,
    ) -> anyhow::Result<Self> {
        let mut p = Self::new(call_url, cookie)?;
        p.auth_token = Some(auth_token);
        Ok(p)
    }
}

#[async_trait]
impl CredentialProvider for VkProvider {
    fn name(&self) -> &'static str {
        "VK Calls"
    }

    async fn obtain(&self) -> anyhow::Result<TurnCredentials> {
        let url = &self.call_url;

        if Path::new(url).exists() && url.ends_with(".json") {
            tracing::info!(file = url, "treating call_url as local JSON file");
            let body = fs::read_to_string(url)?;
            return parse_turn_response(&body);
        }

        tracing::info!(url, "fetching VK call page");
        let body = self.client.get(url).send().await?.text().await?;

        let auth_token = self
            .auth_token
            .clone()
            .or_else(|| find_ok_auth_token_in_page(&body));
        let join_link = find_ok_join_link_in_page(&body).or_else(|| extract_ok_join_link(url));

        if let (Some(token), Some(link)) = (&auth_token, &join_link) {
            tracing::info!("found OK auth_token + join_link, trying OK API flow");
            match self.ok_api_join(token, link).await {
                Ok(c) => return Ok(c),
                Err(e) => tracing::warn!("OK API flow failed: {e}"),
            }
        }

        if let Some(c) = try_turn_server_json(&body)? {
            return Ok(c);
        }
        if let Some(c) = try_ice_servers(&body)? {
            return Ok(c);
        }

        if body.contains("login") || body.contains("al_login") || body.contains("act=login") {
            anyhow::bail!(
                "VK requires authentication (page redirected to login).\n\
                 \n\
                 SOLUTION: Provide the OK auth_token from your browser.\n\
                 1. Open the call in your browser\n\
                 2. Open DevTools -> Console\n\
                 3. Type: `window.config.auth_token` or look in the Network tab for requests to fb.do\n\
                 4. Run turnnel with: --auth-token \"$YOUR_TOKEN\""
            );
        }

        anyhow::bail!("Could not find call data in VK page.")
    }
}

impl VkProvider {
    async fn ok_api_join(
        &self,
        auth_token: &str,
        join_link: &str,
    ) -> anyhow::Result<TurnCredentials> {
        let session_data = serde_json::json!({
            "version": 3,
            "device_id": generate_device_id(),
            "client_version": 1.1,
            "client_type": "SDK_JS",
            "auth_token": auth_token,
        });

        let login_resp = self
            .client
            .post(OK_FB_API)
            .header(ORIGIN, "https://vk.com")
            .header(REFERER, "https://vk.com/")
            .form(&[
                (
                    "session_data",
                    serde_json::to_string(&session_data)?.as_str(),
                ),
                ("method", "auth.anonymLogin"),
                ("format", "JSON"),
                ("application_key", OK_APP_KEY),
            ])
            .send()
            .await?
            .text()
            .await?;

        let session_key = extract_session_key(&login_resp)?;

        let join_resp = self
            .client
            .post(OK_FB_API)
            .header(ORIGIN, "https://vk.com")
            .header(REFERER, "https://vk.com/")
            .form(&[
                ("joinLink", join_link),
                ("isVideo", "false"),
                ("protocolVersion", "5"),
                ("capabilities", "2F7F"),
                ("method", "vchat.joinConversationByLink"),
                ("format", "JSON"),
                ("application_key", OK_APP_KEY),
                ("session_key", &session_key),
            ])
            .send()
            .await?
            .text()
            .await?;

        parse_turn_response(&join_resp)
    }
}

fn find_ok_auth_token_in_page(body: &str) -> Option<String> {
    let re1 = Regex::new(r#""(?:auth_token|token)"\s*:\s*"(\$[a-zA-Z0-9_-]+)""#).ok()?;
    if let Some(caps) = re1.captures(body) {
        return Some(caps.get(1).unwrap().as_str().to_string());
    }
    let re2 = Regex::new(r#""(\$[a-zA-Z0-9_-]{30,})""#).ok()?;
    re2.captures(body)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

fn find_ok_join_link_in_page(body: &str) -> Option<String> {
    let re = Regex::new(r#"(?:joinLink|join_link|callLink)["':\s]+([a-zA-Z0-9_-]{20,})"#).ok()?;
    re.captures(body)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

fn extract_ok_join_link(url: &str) -> Option<String> {
    let re = Regex::new(r#"vk\.com/call/join/([a-zA-Z0-9_-]+)"#).ok()?;
    re.captures(url)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

fn extract_session_key(resp: &str) -> anyhow::Result<String> {
    if let Ok(v) = serde_json::from_str::<Value>(resp) {
        if let Some(key) = v.get("session_key").and_then(|k| k.as_str()) {
            return Ok(key.to_string());
        }
        if let Some(sd) = v.get("session_data") {
            if let Some(key) = sd.get("session_key").and_then(|k| k.as_str()) {
                return Ok(key.to_string());
            }
        }
    }
    anyhow::bail!(
        "no session_key in response: {}",
        &resp[..resp.len().min(200)]
    )
}

fn generate_device_id() -> String {
    use rand::Rng;
    use std::fmt::Write;

    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill(&mut bytes);

    // UUID v4: version and variant bits
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut id = String::with_capacity(36);
    for (i, b) in bytes.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            id.push('-');
        }
        write!(id, "{:02x}", b).unwrap();
    }
    id
}

#[derive(Debug, Deserialize)]
struct TurnServerObj {
    #[serde(default)]
    urls: Vec<String>,
    #[serde(default, alias = "url")]
    url: Option<String>,
    #[serde(default)]
    username: String,
    #[serde(default)]
    credential: String,
}

pub fn parse_turn_response(body: &str) -> anyhow::Result<TurnCredentials> {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        let root = if let Some(inner) = v.get("response") {
            inner
        } else {
            &v
        };
        if let Some(creds) = find_turn_server_recursive(root)? {
            return Ok(creds);
        }
    }

    if let Some(creds) = try_turn_server_json(body)? {
        return Ok(creds);
    }
    if let Some(creds) = try_ice_servers(body)? {
        return Ok(creds);
    }

    if let Ok(v) = serde_json::from_str::<Value>(body) {
        if let Some(err) = v.get("error") {
            let msg = err
                .get("error_msg")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let code = err.get("error_code").and_then(|c| c.as_u64()).unwrap_or(0);
            anyhow::bail!("VK API error {code}: {msg}");
        }
        if let Some(err_msg) = v.get("error_msg").and_then(|m| m.as_str()) {
            anyhow::bail!("OK API error: {err_msg}");
        }
    }

    anyhow::bail!(
        "no turn_server in response (first 300 chars: {})",
        &body[..body.len().min(300)]
    )
}

fn find_turn_server_recursive(v: &Value) -> anyhow::Result<Option<TurnCredentials>> {
    match v {
        Value::Object(map) => {
            if let Some(ts_val) = map.get("turn_server") {
                if let Ok(ts) = serde_json::from_value::<TurnServerObj>(ts_val.clone()) {
                    if let Ok(creds) = turn_server_to_creds(&ts) {
                        return Ok(Some(creds));
                    }
                }
            }
            for (_k, val) in map {
                if let Some(creds) = find_turn_server_recursive(val)? {
                    return Ok(Some(creds));
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                if let Some(creds) = find_turn_server_recursive(item)? {
                    return Ok(Some(creds));
                }
            }
        }
        _ => {}
    }
    Ok(None)
}

fn turn_server_to_creds(ts: &TurnServerObj) -> anyhow::Result<TurnCredentials> {
    let mut all_urls = ts.urls.clone();
    if let Some(ref u) = ts.url {
        all_urls.push(u.clone());
    }
    if all_urls.is_empty() || ts.username.is_empty() {
        anyhow::bail!("turn_server missing urls or username");
    }

    let turn_url = all_urls
        .iter()
        .find(|u| u.starts_with("turn:") || u.starts_with("turns:"))
        .ok_or_else(|| anyhow::anyhow!("no turn: URL in {:?}", all_urls))?;

    let (host, port, _tls) = crate::sdp::parse_turn_uri(turn_url)?;
    let addr = resolve(&host, port)?;

    tracing::info!(server = %addr, user = %ts.username, "VK TURN credentials obtained");

    Ok(TurnCredentials {
        server_addr: addr,
        username: ts.username.clone(),
        password: ts.credential.clone(),
        realm: None,
    })
}

fn try_turn_server_json(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(r#"(?si)"turn_server"\s*:\s*(\{[^}]+\})"#)?;
    if let Some(caps) = re.captures(body) {
        if let Ok(ts) = serde_json::from_str::<TurnServerObj>(caps.get(1).unwrap().as_str()) {
            if let Ok(c) = turn_server_to_creds(&ts) {
                return Ok(Some(c));
            }
        }
    }
    Ok(None)
}

fn try_ice_servers(body: &str) -> anyhow::Result<Option<TurnCredentials>> {
    let re = Regex::new(r#"(?si)"iceServers"\s*:\s*(\[.*?\])\s*[,\}]"#)?;
    if let Some(caps) = re.captures(body) {
        if let Ok(c) = crate::sdp::parse_ice_servers(caps.get(1).unwrap().as_str()) {
            return Ok(Some(c));
        }
    }
    Ok(None)
}

fn resolve(host: &str, port: u16) -> anyhow::Result<SocketAddr> {
    format!("{host}:{port}")
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {host}"))
}
