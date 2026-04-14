//! SMTP server: inbound (port 25) and submission (port 587).
//!
//! Uses mailin-embedded for the SMTP protocol layer. Received messages are sent
//! through a channel to the async processing pipeline (Path A queue or Path B fallback).

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use mailin_embedded::{response, Handler, Response, Server, SslConfig};
use tokio::sync::mpsc;

use crate::server::AppState;

/// A complete message received via SMTP, ready for processing.
pub struct ReceivedMessage {
    pub from: String,
    pub to: Vec<String>,
    pub data: Vec<u8>,
}

/// SMTP handler for inbound mail (port 25).
///
/// Each SMTP connection gets a clone of this handler. Per-connection state
/// (from, to, data buffer) is accumulated during the session, then the
/// complete message is sent through the channel on data_end().
#[derive(Clone)]
struct InboundHandler {
    tx: mpsc::UnboundedSender<ReceivedMessage>,
    mx_hostname: String,
    // Per-connection state (reset on each clone / new connection)
    from: String,
    to: Vec<String>,
    data: Vec<u8>,
}

impl Handler for InboundHandler {
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> Response {
        response::OK
    }

    fn mail(&mut self, _ip: IpAddr, _domain: &str, from: &str) -> Response {
        self.from = from.to_string();
        self.to.clear();
        self.data.clear();
        response::OK
    }

    fn rcpt(&mut self, to: &str) -> Response {
        // Accept all recipients — validation happens async after data_end.
        // This avoids blocking DB lookups in the sync SMTP handler.
        self.to.push(to.to_string());
        response::OK
    }

    fn data_start(
        &mut self,
        _domain: &str,
        _from: &str,
        _is8bit: bool,
        _to: &[String],
    ) -> Response {
        self.data.clear();
        response::OK
    }

    fn data(&mut self, buf: &[u8]) -> io::Result<()> {
        self.data.extend_from_slice(buf);
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        let msg = ReceivedMessage {
            from: self.from.clone(),
            to: self.to.clone(),
            data: std::mem::take(&mut self.data),
        };

        match self.tx.send(msg) {
            Ok(_) => response::OK,
            Err(_) => {
                // Channel closed — server shutting down
                response::INTERNAL_ERROR
            }
        }
    }
}

/// Run the inbound SMTP server (port 25).
///
/// Receives email from external senders for custom domains.
/// Messages are queued for Path A pickup (client-side encryption) with
/// automatic Path B fallback (gateway-side encryption) on TTL expiry.
pub async fn run_smtp_inbound(state: Arc<AppState>) -> anyhow::Result<()> {
    let (tx, rx) = mpsc::unbounded_channel::<ReceivedMessage>();

    let handler = InboundHandler {
        tx,
        mx_hostname: state.config.mx_hostname.clone(),
        from: String::new(),
        to: Vec::new(),
        data: Vec::new(),
    };

    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_smtp_port);
    tracing::info!("SMTP inbound server starting on {}", addr);

    // Spawn the blocking SMTP server in a dedicated thread
    let smtp_addr = addr.clone();
    let mx_name = state.config.mx_hostname.clone();
    let smtp_handle = tokio::task::spawn_blocking(move || {
        let mut server = Server::new(handler);
        server
            .with_name(&mx_name)
            .with_ssl(SslConfig::None)
            .expect("SSL config failed")
            .with_addr(&smtp_addr)
            .expect("Invalid SMTP address");

        if let Err(e) = server.serve() {
            tracing::error!("SMTP inbound server error: {}", e);
        }
    });

    // Process received messages asynchronously
    let process_handle = tokio::spawn(process_inbound_messages(state, rx));

    // Wait for either to finish (normally neither should)
    tokio::select! {
        res = smtp_handle => {
            res?;
        }
        res = process_handle => {
            res??;
        }
    }

    Ok(())
}

/// Process messages received from the SMTP handler.
///
/// For each message:
/// 1. Look up recipient in mail_addresses
/// 2. Write raw message to temp storage
/// 3. Enqueue for Path A pickup (client fetches + encrypts locally)
/// 4. Path B fallback happens automatically via the expiry worker in inbound.rs
async fn process_inbound_messages(
    state: Arc<AppState>,
    mut rx: mpsc::UnboundedReceiver<ReceivedMessage>,
) -> anyhow::Result<()> {
    let temp_dir = std::path::PathBuf::from("/tmp/fula-mail/inbound");
    tokio::fs::create_dir_all(&temp_dir).await?;

    while let Some(msg) = rx.recv().await {
        for recipient in &msg.to {
            if let Err(e) = process_single_recipient(&state, &msg.from, recipient, &msg.data, &temp_dir).await {
                tracing::error!("Failed to process mail for {}: {}", recipient, e);
                // Log delivery failure
                let _ = state.db.log_delivery(
                    "inbound",
                    None,
                    None,
                    &msg.from,
                    recipient,
                    "rejected",
                    None,
                    Some(&e.to_string()),
                    None,
                ).await;
            }
        }
    }

    Ok(())
}

async fn process_single_recipient(
    state: &AppState,
    from: &str,
    to: &str,
    raw_data: &[u8],
    temp_dir: &std::path::Path,
) -> anyhow::Result<()> {
    // Look up recipient
    let addr = state.db.get_address_by_email(to).await?
        .ok_or_else(|| anyhow::anyhow!("Unknown recipient: {}", to))?;

    if addr.domain_status != "active" {
        anyhow::bail!("Domain not active for {}", to);
    }

    // Extract message-id from headers (best-effort)
    let message_id = extract_message_id(raw_data)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Extract subject (best-effort, for queue display)
    let subject = extract_subject(raw_data);

    // Write raw message to temp file
    let temp_path = temp_dir.join(format!("{}.eml", message_id.replace(['<', '>', '/', '\\'], "_")));
    tokio::fs::write(&temp_path, raw_data).await?;

    let storage_path = temp_path.to_string_lossy().to_string();

    // Enqueue for Path A pickup
    let queue_id = state.db.enqueue_inbound(
        addr.id,
        &message_id,
        from,
        subject.as_deref(),
        raw_data.len() as i32,
        &storage_path,
        state.config.path_a_ttl_secs,
    ).await?;

    tracing::info!(
        "Queued inbound mail {} for {} (queue_id={}, Path A TTL={}s)",
        message_id, to, queue_id, state.config.path_a_ttl_secs,
    );

    // Log delivery
    state.db.log_delivery(
        "inbound",
        Some(addr.id),
        Some(&message_id),
        from,
        to,
        "queued",
        None,
        Some("Queued for Path A pickup"),
        None,
    ).await?;

    // TODO: Send push notification to trigger FxMail to pick up the message
    // if addr.push_token.is_some() { send_push_notification(...) }

    Ok(())
}

/// Extract Message-ID header from raw RFC 5322 message.
fn extract_message_id(data: &[u8]) -> Option<String> {
    let parsed = mail_parser::MessageParser::default().parse(data)?;
    parsed.message_id().map(|s| s.to_string())
}

/// Extract Subject header from raw RFC 5322 message.
fn extract_subject(data: &[u8]) -> Option<String> {
    let parsed = mail_parser::MessageParser::default().parse(data)?;
    parsed.subject().map(|s| s.to_string())
}

/// Run the SMTP submission server (port 587).
///
/// Accepts outbound mail from authenticated FxMail/IMAP clients.
/// Flow: authenticate -> DKIM sign with domain key -> SMTP relay.
pub async fn run_smtp_submission(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_submission_port);
    tracing::info!("SMTP submission server will listen on {} (not yet implemented)", addr);

    // TODO: Implement submission server using mailin-embedded with AUTH required
    // For now, outbound submission is handled via the HTTP API (/api/v1/outbound/send)
    // which is simpler for FxMail integration.

    // Keep the task alive
    tokio::signal::ctrl_c().await?;
    Ok(())
}
