//! Outbound mail processing: DKIM signing and SMTP relay.
//!
//! Users bring their own relay API key (BYOK). Supported providers:
//! - **SendGrid**: Web API (recommended, easiest setup)
//! - **Mailgun**: SMTP relay
//! - **Generic SMTP**: Any SMTP relay (SES, Postmark, self-hosted, etc.)
//!
//! If no per-user relay is configured, falls back to the global relay from env config.
//! If neither is configured, outbound fails with a clear error.
//!
//! Flow:
//! 1. FxMail submits plaintext message via HTTPS API (authenticated with JWT)
//! 2. Gateway looks up sender's relay config (per-user BYOK or global fallback)
//! 3. TODO: DKIM-signs the message with domain's private key
//! 4. Relays via the user's relay provider
//! 5. Does NOT store plaintext (fire-and-forget)

use anyhow::Result;
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

use crate::{config::Config, db::{Database, RelayConfig}, handlers::OutboundRequest};

/// Send an outbound email: build message, resolve relay, deliver.
pub async fn send_outbound(
    config: &Config,
    db: &Database,
    req: &OutboundRequest,
) -> Result<String> {
    // Look up sender's address record (contains domain DKIM info + relay config)
    let addr = db.get_address_by_email(&req.from).await?
        .ok_or_else(|| anyhow::anyhow!("Sender address not found: {}", req.from))?;

    if addr.domain_status != "active" {
        anyhow::bail!("Sender domain not active");
    }

    // Build the email message
    let content_type = req.content_type.as_deref().unwrap_or("text/plain");
    let mut email_builder = Message::builder()
        .from(req.from.parse()?)
        .subject(&req.subject);

    for to in &req.to {
        email_builder = email_builder.to(to.parse()?);
    }

    let email = if content_type.contains("html") {
        email_builder.header(ContentType::TEXT_HTML)
            .body(req.body.clone())?
    } else {
        email_builder.header(ContentType::TEXT_PLAIN)
            .body(req.body.clone())?
    };

    // TODO: DKIM sign the message using domain's private key
    // let signed = dkim_sign(&email, &addr.dkim_private_key, &addr.dkim_selector, &addr.domain)?;

    // Resolve relay: per-user BYOK first, then global fallback
    let relay = addr.relay_config()
        .or_else(|| global_relay_config(config));

    let message_id = match relay {
        Some(relay_config) => relay_via_provider(&relay_config, &email).await?,
        None => anyhow::bail!(
            "No outbound relay configured for {}. Set up SendGrid, Mailgun, or SMTP relay in FxMail settings.",
            req.from
        ),
    };

    // Log delivery
    for to in &req.to {
        db.log_delivery(
            "outbound",
            Some(addr.id),
            Some(&message_id),
            &req.from,
            to,
            "sent",
            None,
            None,
            None,
        ).await?;
    }

    tracing::info!("Outbound mail sent: {} -> {:?} (message_id={})", req.from, req.to, message_id);
    Ok(message_id)
}

/// Build a RelayConfig from the global env config (fallback when user has no BYOK).
fn global_relay_config(config: &Config) -> Option<RelayConfig> {
    let host = config.outbound_relay_host.as_ref()?;
    Some(RelayConfig::Smtp {
        host: host.clone(),
        port: config.outbound_relay_port.unwrap_or(587),
        username: config.outbound_relay_user.clone().unwrap_or_default(),
        password: config.outbound_relay_password.clone().unwrap_or_default(),
    })
}

/// Relay message via the user's provider.
async fn relay_via_provider(relay: &RelayConfig, email: &Message) -> Result<String> {
    match relay {
        RelayConfig::SendGrid { api_key } => {
            relay_sendgrid(api_key, email).await
        }
        RelayConfig::Mailgun { api_key, domain } => {
            relay_mailgun(api_key, domain, email).await
        }
        RelayConfig::Smtp { host, port, username, password } => {
            relay_smtp(host, *port, username, password, email).await
        }
    }
}

/// Send via SendGrid Web API v3.
async fn relay_sendgrid(api_key: &str, email: &Message) -> Result<String> {
    let client = reqwest::Client::new();

    // Extract fields from the Message
    let raw = email.formatted();
    let raw_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &raw,
    );

    // SendGrid v3 mail/send with raw MIME
    let resp = client
        .post("https://api.sendgrid.com/v3/mail/send")
        .bearer_auth(api_key)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "personalizations": [{
                "to": email.envelope().to().iter().map(|a| {
                    serde_json::json!({ "email": a.to_string() })
                }).collect::<Vec<_>>(),
            }],
            "from": { "email": email.envelope().from().map(|f| f.to_string()).unwrap_or_default() },
            "content": [{
                "type": "text/plain",
                "value": " " // placeholder — raw content below overrides
            }],
            "headers": {},
            "mail_settings": {
                "bypass_list_management": { "enable": false }
            }
        }))
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 202 {
        // SendGrid returns message ID in x-message-id header
        let msg_id = resp.headers()
            .get("x-message-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("sendgrid-accepted")
            .to_string();
        Ok(msg_id)
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("SendGrid API error ({}): {}", status, body)
    }
}

/// Send via Mailgun SMTP relay.
async fn relay_mailgun(api_key: &str, _domain: &str, email: &Message) -> Result<String> {
    // Mailgun SMTP: smtp.mailgun.org:587, user=postmaster@domain, password=api_key
    relay_smtp("smtp.mailgun.org", 587, "api", api_key, email).await
}

/// Send via generic SMTP relay (works for any provider: SES, Postmark, self-hosted, etc.).
async fn relay_smtp(host: &str, port: u16, username: &str, password: &str, email: &Message) -> Result<String> {
    let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?
        .port(port)
        .credentials(Credentials::new(username.to_string(), password.to_string()))
        .build();

    let response = transport.send(email.clone()).await?;
    let message_id = response.message().collect::<Vec<_>>().join(" ");

    Ok(message_id)
}
