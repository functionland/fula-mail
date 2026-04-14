//! Outbound mail processing: DKIM signing and SMTP relay.
//!
//! Flow:
//! 1. FxMail submits plaintext message via HTTPS API (authenticated with JWT)
//! 2. Gateway looks up sender's domain DKIM key
//! 3. DKIM-signs the message
//! 4. Relays via SMTP (direct or via outbound relay for IP warming)
//! 5. Does NOT store plaintext (fire-and-forget)

use anyhow::Result;
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};

use crate::{config::Config, db::Database, handlers::OutboundRequest};

/// Send an outbound email: build message, DKIM sign, relay via SMTP.
pub async fn send_outbound(
    config: &Config,
    db: &Database,
    req: &OutboundRequest,
) -> Result<String> {
    // Look up sender's address record (contains domain DKIM info)
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

    // Relay via SMTP
    let message_id = relay_smtp(config, &email).await?;

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

/// Relay message via SMTP (either outbound relay or direct delivery).
async fn relay_smtp(config: &Config, email: &Message) -> Result<String> {
    let transport = if let Some(relay_host) = &config.outbound_relay_host {
        // Use configured relay (SendGrid, Mailgun, etc.) for IP warming
        let port = config.outbound_relay_port.unwrap_or(587);
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(relay_host)?
            .port(port);

        if let (Some(user), Some(pass)) = (&config.outbound_relay_user, &config.outbound_relay_password) {
            builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
        }

        builder.build()
    } else {
        // Direct delivery — resolve recipient MX and connect
        // For production, this requires proper IP reputation
        anyhow::bail!("Direct SMTP delivery not yet implemented. Configure OUTBOUND_RELAY_HOST for relay mode.");
    };

    let response = transport.send(email.clone()).await?;
    let message_id = response.message().collect::<Vec<_>>().join(" ");

    Ok(message_id)
}
