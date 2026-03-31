use async_trait::async_trait;
use turnnel_session::session::TurnCredentials;

use crate::CredentialProvider;

pub struct ManualProvider {
    credentials: TurnCredentials,
}

impl ManualProvider {
    pub fn new(credentials: TurnCredentials) -> Self {
        Self { credentials }
    }
}

#[async_trait]
impl CredentialProvider for ManualProvider {
    fn name(&self) -> &'static str {
        "Manual"
    }

    async fn obtain(&self) -> anyhow::Result<TurnCredentials> {
        Ok(self.credentials.clone())
    }
}
