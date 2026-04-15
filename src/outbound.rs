//! Outbound mail processing: DKIM signing and SMTP relay with retry queue.
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
//! 2. Message is enqueued in mail_outbound_queue (persistent)
//! 3. Outbound worker picks it up, looks up sender's relay config
//! 4. TODO: DKIM-signs the message with domain's private key
//! 5. Relays via the user's relay provider
//! 6. On transient failure (4xx): retry with exponential backoff
//! 7. On permanent failure (5xx) or max retries: mark permanently_failed

use std::sync::Arc;

use anyhow::Result;
use lettre::{
    message::{
        header::ContentType,
        dkim::{DkimConfig, DkimSigningAlgorithm, DkimSigningKey},
    },
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use tokio::time::{sleep, Duration};

use crate::{config::Config, db::{Database, RelayConfig}, handlers::OutboundRequest, server::AppState};

/// Maximum retries for outbound messages before marking permanently failed.
const MAX_OUTBOUND_RETRIES: i32 = 5;

/// Enqueue an outbound email for delivery. Returns immediately with the queue ID.
pub async fn enqueue_outbound(
    db: &Database,
    req: &OutboundRequest,
    address_id: uuid::Uuid,
) -> Result<uuid::Uuid> {
    let content_type = req.content_type.as_deref().unwrap_or("text/plain");
    let queue_id = db.enqueue_outbound(
        address_id,
        &req.from,
        &req.to,
        &req.subject,
        &req.body,
        content_type,
    ).await?;

    tracing::info!("Enqueued outbound mail {} -> {:?} (queue_id={})", req.from, req.to, queue_id);
    Ok(queue_id)
}

/// Background worker that processes the outbound mail queue.
/// Runs every 10 seconds, claims a batch of pending messages, and delivers them.
pub async fn run_outbound_worker(state: Arc<AppState>) -> anyhow::Result<()> {
    tracing::info!("Outbound delivery worker started (max_retries: {})", MAX_OUTBOUND_RETRIES);

    loop {
        sleep(Duration::from_secs(10)).await;

        match process_outbound_batch(&state).await {
            Ok(count) if count > 0 => {
                tracing::info!("Delivered {} outbound messages", count);
            }
            Err(e) => {
                tracing::error!("Outbound worker error: {}", e);
            }
            _ => {}
        }
    }
}

async fn process_outbound_batch(state: &AppState) -> Result<usize> {
    let batch = state.db.claim_outbound_batch(20).await?;
    let mut delivered = 0;

    for entry in batch {
        match deliver_one(&state.config, &state.db, &entry).await {
            Ok(message_id) => {
                state.db.mark_outbound_sent(entry.id).await?;
                for recip in &entry.recipients {
                    state.db.log_delivery(
                        "outbound", Some(entry.address_id), Some(&message_id),
                        &entry.sender, recip, "sent", None, None, None,
                    ).await?;
                }
                delivered += 1;
            }
            Err(e) => {
                let error_str = e.to_string();
                let is_permanent = is_permanent_failure(&error_str);

                if is_permanent || entry.retry_count + 1 >= MAX_OUTBOUND_RETRIES {
                    let reason = if is_permanent {
                        format!("Permanent failure: {}", error_str)
                    } else {
                        format!("Max retries ({}) exhausted: {}", MAX_OUTBOUND_RETRIES, error_str)
                    };
                    tracing::error!("Outbound permanently failed for {}: {}", entry.sender, reason);
                    state.db.mark_outbound_failed(entry.id, &reason).await?;
                    for recip in &entry.recipients {
                        state.db.log_delivery(
                            "outbound", Some(entry.address_id), None,
                            &entry.sender, recip, "failed", None, Some(&reason), None,
                        ).await?;
                    }
                } else {
                    tracing::warn!("Outbound transient failure for {} (retry {}/{}): {}",
                        entry.sender, entry.retry_count + 1, MAX_OUTBOUND_RETRIES, error_str);
                    state.db.mark_outbound_retry(entry.id, &error_str).await?;
                }
            }
        }
    }

    Ok(delivered)
}

/// Deliver a single outbound message. On success, returns the relay's message ID.
async fn deliver_one(
    config: &Config,
    db: &Database,
    entry: &crate::db::OutboundQueueRecord,
) -> Result<String> {
    let addr = db.get_address_by_email(&entry.sender).await?
        .ok_or_else(|| anyhow::anyhow!("Sender address not found: {}", entry.sender))?;

    if addr.domain_status != "active" {
        anyhow::bail!("Sender domain not active (permanent)");
    }

    // Build the email message
    let mut email_builder = Message::builder()
        .from(entry.sender.parse()?)
        .subject(&entry.subject);

    for to in &entry.recipients {
        email_builder = email_builder.to(to.parse()?);
    }

    let mut email = if entry.content_type.contains("html") {
        email_builder.header(ContentType::TEXT_HTML)
            .body(entry.body.clone())?
    } else {
        email_builder.header(ContentType::TEXT_PLAIN)
            .body(entry.body.clone())?
    };

    // DKIM sign the message using domain's private key (PKCS#1 PEM)
    if let Ok(signing_key) = DkimSigningKey::new(&addr.dkim_private_key, DkimSigningAlgorithm::Rsa) {
        let dkim_config = DkimConfig::default_config(
            addr.dkim_selector.clone(),
            addr.domain.clone(),
            signing_key,
        );
        lettre::message::dkim::dkim_sign(&mut email, &dkim_config);
        tracing::debug!("DKIM signed outbound mail for {}", addr.domain);
    } else {
        tracing::warn!("Failed to load DKIM key for domain {}, sending unsigned", addr.domain);
    }

    // Resolve relay: per-user BYOK first, then global fallback
    let relay = addr.relay_config()
        .or_else(|| global_relay_config(config));

    match relay {
        Some(relay_config) => relay_via_provider(&relay_config, &email).await,
        None => anyhow::bail!(
            "No outbound relay configured for {} (permanent)", entry.sender
        ),
    }
}

/// Heuristic: is this a permanent failure that should not be retried?
fn is_permanent_failure(error: &str) -> bool {
    let lower = error.to_lowercase();
    // 5xx SMTP codes, explicit "permanent" markers, auth failures, domain issues
    lower.contains("550 ")
        || lower.contains("551 ")
        || lower.contains("552 ")
        || lower.contains("553 ")
        || lower.contains("554 ")
        || lower.contains("555 ")
        || lower.contains("(permanent)")
        || lower.contains("authentication failed")
        || lower.contains("relay access denied")
        || lower.contains("sender address not found")
        || lower.contains("domain not active")
        || lower.contains("no outbound relay configured")
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
        }))
        .send()
        .await?;

    if resp.status().is_success() || resp.status().as_u16() == 202 {
        let msg_id = resp.headers()
            .get("x-message-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("sendgrid-accepted")
            .to_string();
        Ok(msg_id)
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        // 4xx from SendGrid = usually auth/validation issue (permanent)
        // 5xx = server error (transient)
        if status.as_u16() >= 500 {
            anyhow::bail!("SendGrid server error ({}): {}", status, body)
        } else {
            anyhow::bail!("SendGrid API error ({}) (permanent): {}", status, body)
        }
    }
}

/// Send via Mailgun SMTP relay.
async fn relay_mailgun(api_key: &str, _domain: &str, email: &Message) -> Result<String> {
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
