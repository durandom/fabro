use async_trait::async_trait;
use fabro_model::Provider;
use fabro_static::EnvVars;

use crate::context::{AuthContextRequest, AuthContextResponse};
use crate::credential::{AuthCredential, AuthDetails};
use crate::strategy::AuthStrategy;

pub struct ClaudeCodeOAuthStrategy;

impl ClaudeCodeOAuthStrategy {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for ClaudeCodeOAuthStrategy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AuthStrategy for ClaudeCodeOAuthStrategy {
    async fn init(&mut self) -> anyhow::Result<AuthContextRequest> {
        Ok(AuthContextRequest::ApiKey {
            provider:      Provider::Anthropic,
            env_var_names: vec![EnvVars::CLAUDE_CODE_OAUTH_TOKEN.to_string()],
        })
    }

    async fn complete(&mut self, response: AuthContextResponse) -> anyhow::Result<AuthCredential> {
        match response {
            AuthContextResponse::ApiKey { key } => {
                let token = key.trim().to_string();
                anyhow::ensure!(!token.is_empty(), "OAuth token is empty");
                Ok(AuthCredential {
                    provider: Provider::Anthropic,
                    details:  AuthDetails::ClaudeCodeOAuth { token },
                })
            }
            AuthContextResponse::DeviceCodeConfirmed => {
                Err(anyhow::anyhow!("expected OAuth token response"))
            }
        }
    }
}
