use async_trait::async_trait;
use regex::Regex;
use reqwest::Client;
use turnnel_session::session::TurnCredentials;

use crate::CredentialProvider;

pub struct YandexProvider {
    pub call_url: String,
    client: Client,
}

impl YandexProvider {
    pub fn new(call_url: impl Into<String>) -> Self {
        Self {
            call_url: call_url.into(),
            client: Client::new(),
        }
    }
}

#[async_trait]
impl CredentialProvider for YandexProvider {
    fn name(&self) -> &'static str {
        "Yandex Telemost"
    }

    async fn obtain(&self) -> anyhow::Result<TurnCredentials> {
        tracing::info!(url = %self.call_url, "fetching Yandex Telemost page");

        let body = self.client.get(&self.call_url).send().await?.text().await?;

        // Look for the iceServers array embedded in the page HTML / JS
        let re = Regex::new(r#"(?si)"iceServers"\s*:\s*(\[.*?\])"#)?;

        if let Some(caps) = re.captures(&body) {
            let json = caps.get(1).unwrap().as_str();
            return crate::sdp::parse_ice_servers(json);
        }

        anyhow::bail!("TURN credentials not found in Yandex Telemost page")
    }
}
