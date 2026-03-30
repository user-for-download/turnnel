pub mod manual;
pub mod sdp;
pub mod vk;
pub mod yandex;

use async_trait::async_trait;
use turnnel_session::session::TurnCredentials;

#[async_trait]
pub trait CredentialProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn obtain(&self) -> anyhow::Result<TurnCredentials>;
}
