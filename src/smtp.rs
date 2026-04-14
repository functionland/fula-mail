//! SMTP server stubs for inbound and submission (outbound).
//!
//! TODO: Integrate with Stalwart's SMTP implementation or build custom
//! using mailin-embedded / smtp-server crate.

use std::sync::Arc;
use crate::server::AppState;

/// Run the inbound SMTP server (port 25).
///
/// Receives email from external senders (Gmail, Outlook, etc.) for custom domains.
/// Flow: SMTP receive -> queue for Path A pickup (or Path B fallback encryption).
pub async fn run_smtp_inbound(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_smtp_port);
    tracing::info!("SMTP inbound server will listen on {} (not yet implemented)", addr);

    // TODO: Implement SMTP server
    // 1. Accept SMTP connections with STARTTLS
    // 2. Validate recipient against mail_addresses table
    // 3. SPF/DKIM/DMARC check on sender
    // 4. Spam filtering (rspamd integration)
    // 5. If recipient has push_token -> enqueue for Path A, send push notification
    // 6. If no push_token or Path A TTL expires -> Path B (encrypt with pubkey, pin)
    // 7. Log delivery to mail_delivery_log

    // Keep the task alive
    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// Run the SMTP submission server (port 587).
///
/// Accepts outbound mail from authenticated FxMail/IMAP clients.
/// Flow: authenticate -> DKIM sign with user's domain key -> SMTP relay.
pub async fn run_smtp_submission(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_submission_port);
    tracing::info!("SMTP submission server will listen on {} (not yet implemented)", addr);

    // TODO: Implement submission server
    // 1. Require STARTTLS + authentication (JWT or SASL)
    // 2. Validate sender owns the From address
    // 3. Look up domain's DKIM private key
    // 4. DKIM-sign the message
    // 5. If outbound relay configured -> relay via SendGrid/Mailgun (for IP warming)
    // 6. Otherwise -> direct SMTP delivery to recipient's MX
    // 7. Log delivery to mail_delivery_log

    // Keep the task alive
    tokio::signal::ctrl_c().await?;
    Ok(())
}
