use std::fmt::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use turnnel_session::session::TurnCredentials;

use crate::CredentialProvider;

const VK_CLIENT_ID: &str = "6287487";
const VK_CLIENT_SECRET: &str = "QbYic1K3lEV5kTGiqlq2";
const VK_APP_ID: &str = "6287487";
const VK_API_VERSION: &str = "5.274";

const VK_ANON_TOKEN_URL: &str = "https://login.vk.ru/?act=get_anonym_token";
const VK_CALLS_TOKEN_URL: &str = "https://api.vk.ru/method/calls.getAnonymousToken";

const OK_API_URL: &str = "https://calls.okcdn.ru/fb.do";
const OK_APP_KEY: &str = "CGMMEJLGDIHBABABA";

const OK_SESSION_VERSION: u32 = 2;
const OK_CLIENT_VERSION: f64 = 1.1;
const OK_CLIENT_TYPE: &str = "SDK_JS";
const OK_PROTOCOL_VERSION: &str = "5";

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) \
                   Gecko/20100101 Firefox/144.0";
const FORM_CT: &str = "application/x-www-form-urlencoded";
const HTTP_TIMEOUT: Duration = Duration::from_secs(20);

// ═══════════════════════════════════════════════════════════════════════════
//  Provider
// ═══════════════════════════════════════════════════════════════════════════

pub struct VkProvider {
    join_link: String,
    call_url: String,
    auth_token: Option<String>,
    client: Client,
}

impl VkProvider {
    pub fn new(call_url: impl Into<String>, _cookie: Option<String>) -> anyhow::Result<Self> {
        let call_url: String = call_url.into();
        // Issue 4: complete the format string
        let join_link = extract_join_link(&call_url).ok_or_else(|| {
            anyhow::anyhow!(
                "could not extract join link from: {call_url}\n\
                 Expected format: https://vk.com/call/join/<link>"
            )
        })?;

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_static(UA));

        let client = Client::builder()
            .default_headers(headers)
            .timeout(HTTP_TIMEOUT)
            .build()?;

        Ok(Self {
            join_link,
            call_url,
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
        tracing::info!(link = %self.join_link, "trying anonymous VK Calls flow");
        match self.anonymous_flow().await {
            Ok(creds) => return Ok(creds),
            Err(e) => tracing::warn!("anonymous flow failed: {e:#}"),
        }

        if let Some(ref token) = self.auth_token {
            tracing::info!("trying auth_token-based OK API flow");
            match self.auth_token_flow(token).await {
                Ok(creds) => return Ok(creds),
                Err(e) => tracing::warn!("auth_token flow failed: {e:#}"),
            }
        }

        tracing::info!(url = %self.call_url, "trying page-scraping fallback");
        match self.page_scrape_flow().await {
            Ok(creds) => return Ok(creds),
            Err(e) => tracing::warn!("page scraping failed: {e:#}"),
        }

        anyhow::bail!(
            "all VK credential flows failed for link '{}'\n\n\
             Possible causes:\n\
             • The call link has expired or is invalid\n\
             • VK has changed their API (update constants in vk.rs)\n\
             • Network issues (VK/OK domains may be blocked)\n\n\
             You can also try: --auth-token <TOKEN>",
            self.join_link
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Anonymous 4-step flow
// ═══════════════════════════════════════════════════════════════════════════

impl VkProvider {
    async fn anonymous_flow(&self) -> anyhow::Result<TurnCredentials> {
        let vk_token = self.step1_vk_anon_token().await?;
        tracing::debug!("step 1/4 ✓  VK anon access_token");

        let anonym_token = self.step2_call_anon_token(&vk_token).await?;
        tracing::debug!("step 2/4 ✓  call anonymToken");

        let session_key = self.step3_ok_session_key().await?;
        tracing::debug!("step 3/4 ✓  OK session_key");

        let creds = self.step4_join_call(&anonym_token, &session_key).await?;
        tracing::debug!("step 4/4 ✓  TURN credentials");

        Ok(creds)
    }

    async fn step1_vk_anon_token(&self) -> anyhow::Result<String> {
        let body = format!(
            "client_id={VK_CLIENT_ID}\
             &token_type=messages\
             &client_secret={VK_CLIENT_SECRET}\
             &version=1\
             &app_id={VK_APP_ID}"
        );

        let text = self
            .client
            .post(VK_ANON_TOKEN_URL)
            .header("Content-Type", FORM_CT)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        let resp: Value = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!("step 1: invalid JSON: {e}\nbody: {}", trunc_str(&text, 300))
        })?;

        resp["data"]["access_token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("step 1: no data.access_token — {}", trunc(&resp, 300)))
    }

    async fn step2_call_anon_token(&self, vk_token: &str) -> anyhow::Result<String> {
        let url = format!("{VK_CALLS_TOKEN_URL}?v={VK_API_VERSION}&client_id={VK_CLIENT_ID}");

        // Issue 4: complete the URL format string
        let body = format!(
            "vk_join_link=https://vk.com/call/join/{}\
             &name=123\
             &access_token={vk_token}",
            self.join_link
        );

        let text = self
            .client
            .post(&url)
            .header("Content-Type", FORM_CT)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        let resp: Value = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!("step 2: invalid JSON: {e}\nbody: {}", trunc_str(&text, 300))
        })?;

        if let Some(err) = resp.get("error") {
            let msg = err
                .get("error_msg")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let code = err.get("error_code").and_then(|c| c.as_u64()).unwrap_or(0);
            anyhow::bail!("step 2: VK API error {code}: {msg}");
        }

        resp["response"]["token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("step 2: no response.token — {}", trunc(&resp, 300)))
    }

    async fn step3_ok_session_key(&self) -> anyhow::Result<String> {
        let device_id = uuid_v4();

        let session_data = serde_json::json!({
            "version": OK_SESSION_VERSION,
            "device_id": device_id,
            "client_version": OK_CLIENT_VERSION,
            "client_type": OK_CLIENT_TYPE,
        });
        let session_json = serde_json::to_string(&session_data)?;

        let body = format!(
            "session_data={}\
             &method=auth.anonymLogin\
             &format=JSON\
             &application_key={OK_APP_KEY}",
            percent_encode(&session_json)
        );

        let text = self
            .client
            .post(OK_API_URL)
            .header("Content-Type", FORM_CT)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        let resp: Value = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!("step 3: invalid JSON: {e}\nbody: {}", trunc_str(&text, 300))
        })?;

        resp["session_key"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| anyhow::anyhow!("step 3: no session_key — {}", trunc(&resp, 300)))
    }

    async fn step4_join_call(
        &self,
        anonym_token: &str,
        session_key: &str,
    ) -> anyhow::Result<TurnCredentials> {
        let body = format!(
            "joinLink={}\
             &isVideo=false\
             &protocolVersion={OK_PROTOCOL_VERSION}\
             &anonymToken={anonym_token}\
             &method=vchat.joinConversationByLink\
             &format=JSON\
             &application_key={OK_APP_KEY}\
             &session_key={session_key}",
            self.join_link
        );

        let text = self
            .client
            .post(OK_API_URL)
            .header("Content-Type", FORM_CT)
            .body(body)
            .send()
            .await?
            .text()
            .await?;

        let resp: Value = serde_json::from_str(&text).map_err(|e| {
            anyhow::anyhow!("step 4: invalid JSON: {e}\nbody: {}", trunc_str(&text, 300))
        })?;

        if let Some(msg) = resp.get("error_msg").and_then(|m| m.as_str()) {
            anyhow::bail!("step 4: OK API error: {msg}");
        }

        parse_turn_from_value(&resp)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  Fallback flows
// ═══════════════════════════════════════════════════════════════════════════

impl VkProvider {
    async fn auth_token_flow(&self, auth_token: &str) -> anyhow::Result<TurnCredentials> {
        let device_id = uuid_v4();
        let session_data = serde_json::json!({
            "version": OK_SESSION_VERSION,
            "device_id": device_id,
            "client_version": OK_CLIENT_VERSION,
            "client_type": OK_CLIENT_TYPE,
            "auth_token": auth_token,
        });
        let sd_str = serde_json::to_string(&session_data)?;

        let login_text = self
            .client
            .post(OK_API_URL)
            .header("Content-Type", FORM_CT)
            .form(&[
                ("session_data", sd_str.as_str()),
                ("method", "auth.anonymLogin"),
                ("format", "JSON"),
                ("application_key", OK_APP_KEY),
            ])
            .send()
            .await?
            .text()
            .await?;

        let login_resp: Value = serde_json::from_str(&login_text)
            .map_err(|e| anyhow::anyhow!("auth flow login: invalid JSON: {e}"))?;

        let session_key = login_resp["session_key"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no session_key: {}", trunc(&login_resp, 200)))?;

        let join_text = self
            .client
            .post(OK_API_URL)
            .header("Content-Type", FORM_CT)
            .form(&[
                ("joinLink", self.join_link.as_str()),
                ("isVideo", "false"),
                ("protocolVersion", OK_PROTOCOL_VERSION),
                ("method", "vchat.joinConversationByLink"),
                ("format", "JSON"),
                ("application_key", OK_APP_KEY),
                ("session_key", session_key),
            ])
            .send()
            .await?
            .text()
            .await?;

        let join_resp: Value = serde_json::from_str(&join_text)
            .map_err(|e| anyhow::anyhow!("auth flow join: invalid JSON: {e}"))?;

        parse_turn_from_value(&join_resp)
    }

    async fn page_scrape_flow(&self) -> anyhow::Result<TurnCredentials> {
        let body = self.client.get(&self.call_url).send().await?.text().await?;

        if let Some(c) = try_turn_server_json(&body)? {
            return Ok(c);
        }
        if let Some(c) = try_ice_servers(&body)? {
            return Ok(c);
        }

        if body.contains("act=login") || body.contains("al_login") {
            anyhow::bail!("page redirected to login — try --auth-token");
        }

        anyhow::bail!("no TURN data found in page HTML")
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TURN response parsing
// ═══════════════════════════════════════════════════════════════════════════

fn parse_turn_from_value(resp: &Value) -> anyhow::Result<TurnCredentials> {
    let ts = resp
        .get("turn_server")
        .ok_or_else(|| anyhow::anyhow!("no turn_server in response: {}", trunc(resp, 300)))?;

    let username = ts["username"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no turn_server.username"))?;

    let credential = ts["credential"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no turn_server.credential"))?;

    let url_raw = ts["urls"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no turn_server.urls[0]"))?;

    let clean = url_raw.split('?').next().unwrap_or(url_raw);
    let address = clean
        .strip_prefix("turns:")
        .or_else(|| clean.strip_prefix("turn:"))
        .unwrap_or(clean);

    let addr = resolve(address)?;
    tracing::info!(server = %addr, user = %username, "TURN credentials obtained");

    Ok(TurnCredentials {
        server_addr: addr,
        username: username.to_string(),
        password: credential.to_string(),
        realm: None,
    })
}

pub fn parse_turn_response(body: &str) -> anyhow::Result<TurnCredentials> {
    let v: Value = serde_json::from_str(body)?;

    if v.get("turn_server").is_some() {
        return parse_turn_from_value(&v);
    }
    if let Some(inner) = v.get("response") {
        if inner.get("turn_server").is_some() {
            return parse_turn_from_value(inner);
        }
    }
    if let Some(creds) = find_turn_server_recursive(&v)? {
        return Ok(creds);
    }

    if let Some(err) = v.get("error") {
        let msg = err
            .get("error_msg")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        let code = err.get("error_code").and_then(|c| c.as_u64()).unwrap_or(0);
        anyhow::bail!("VK API error {code}: {msg}");
    }
    if let Some(msg) = v.get("error_msg").and_then(|m| m.as_str()) {
        anyhow::bail!("OK API error: {msg}");
    }

    anyhow::bail!(
        "no turn_server found (first 300 chars: {})",
        &body[..body.len().min(300)]
    )
}

// ═══════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn extract_join_link(url: &str) -> Option<String> {
    if !url.contains('/') && !url.contains(':') && !url.is_empty() {
        let clean = url.split(|c: char| c == '?' || c == '#').next()?;
        if !clean.is_empty() {
            return Some(clean.to_string());
        }
    }
    let re = Regex::new(r"(?:call/join/|join/)([a-zA-Z0-9_-]+)").ok()?;
    re.captures(url)
        .map(|c| c.get(1).unwrap().as_str().to_string())
}

fn uuid_v4() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut b = [0u8; 16];
    rng.fill(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;

    let mut s = String::with_capacity(36);
    for (i, byte) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        write!(s, "{:02x}", byte).unwrap();
    }
    s
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                write!(out, "%{:02X}", byte).unwrap();
            }
        }
    }
    out
}

fn trunc(v: &Value, max: usize) -> String {
    let s = v.to_string();
    if s.len() > max {
        format!("{}…", &s[..max])
    } else {
        s
    }
}

fn trunc_str(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max])
    } else {
        s.to_string()
    }
}

fn resolve(address: &str) -> anyhow::Result<SocketAddr> {
    address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve {address}"))
}

// ── Page-scraping helpers ────────────────────────────────────────────────

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

fn find_turn_server_recursive(v: &Value) -> anyhow::Result<Option<TurnCredentials>> {
    match v {
        Value::Object(map) => {
            if let Some(ts_val) = map.get("turn_server") {
                if let Ok(ts) = serde_json::from_value::<TurnServerObj>(ts_val.clone()) {
                    if let Ok(creds) = turn_server_obj_to_creds(&ts) {
                        return Ok(Some(creds));
                    }
                }
            }
            for val in map.values() {
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

fn turn_server_obj_to_creds(ts: &TurnServerObj) -> anyhow::Result<TurnCredentials> {
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
        .ok_or_else(|| anyhow::anyhow!("no turn: URL in {all_urls:?}"))?;

    let (host, port, _tls) = crate::sdp::parse_turn_uri(turn_url)?;
    let addr = resolve(&format!("{host}:{port}"))?;

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
            if let Ok(c) = turn_server_obj_to_creds(&ts) {
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