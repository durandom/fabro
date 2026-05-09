use anyhow::{Result, bail};
use fabro_api::types;
use fabro_auth::{AuthMethod, credential_id_for};
use fabro_model::Provider;
use fabro_util::terminal::Styles;

use crate::args::{ProviderLoginArgs, ProviderLoginMethod};
use crate::command_context::CommandContext;
use crate::shared::provider_auth;

pub(super) async fn login_command(
    args: ProviderLoginArgs,
    base_ctx: &CommandContext,
) -> Result<()> {
    base_ctx.require_no_json_override()?;
    let printer = base_ctx.printer();
    let s = Styles::detect_stderr();
    let ctx = base_ctx.with_target(&args.target)?;
    let server = ctx.server().await?;
    let credential = match (args.method, args.api_key_stdin) {
        (Some(ProviderLoginMethod::ClaudeOauth), true) => {
            bail!("--api-key-stdin is not supported with --method claude-oauth")
        }
        (Some(ProviderLoginMethod::ClaudeOauth), false) => {
            if args.provider != Provider::Anthropic {
                bail!("--method claude-oauth is only valid for --provider anthropic");
            }
            provider_auth::authenticate_provider_with_method(
                args.provider,
                AuthMethod::ClaudeCodeOAuth,
                &s,
                printer,
            )
            .await?
        }
        (Some(ProviderLoginMethod::ApiKey), true) | (None, true) => {
            provider_auth::authenticate_provider_with_api_key_source(
                args.provider,
                provider_auth::ApiKeySource::Stdin,
                &s,
                printer,
            )
            .await?
        }
        (Some(ProviderLoginMethod::ApiKey), false) => {
            provider_auth::authenticate_provider_with_method(
                args.provider,
                AuthMethod::ApiKey,
                &s,
                printer,
            )
            .await?
        }
        (None, false) => provider_auth::authenticate_provider(args.provider, &s, printer).await?,
    };
    let credential_id = credential_id_for(&credential).map_err(anyhow::Error::msg)?;
    let value = serde_json::to_string(&credential)?;

    server
        .create_secret(types::CreateSecretRequest {
            name: credential_id.clone(),
            value,
            type_: types::SecretType::Credential,
            description: None,
        })
        .await?;
    fabro_util::printerr!(
        printer,
        "  {} Saved {}",
        s.green.apply_to("✔"),
        credential_id
    );
    Ok(())
}
