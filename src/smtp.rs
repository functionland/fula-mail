//! SMTP server: inbound (port 25).
//!
//! Uses mailin-embedded for the SMTP protocol layer. Received messages are sent
//! through a channel to the async processing pipeline (Path A queue or Path B fallback).

use std::collections::HashSet;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use mailin_embedded::{response, Handler, Response, Server, SslConfig};
use tokio::sync::{mpsc, RwLock};

use crate::server::AppState;

/// Maximum recipients per SMTP session (prevents abuse).
const MAX_RECIPIENTS_PER_MESSAGE: usize = 100;

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
    /// Known domains for recipient validation (refreshed periodically).
    known_domains: Arc<RwLock<HashSet<String>>>,
    /// Maximum message size in bytes.
    max_message_size: usize,
    // Per-connection state (reset on each clone / new connection)
    from: String,
    to: Vec<String>,
    data: Vec<u8>,
    data_size: usize,
    size_exceeded: bool,
}

impl Handler for InboundHandler {
    fn helo(&mut self, _ip: IpAddr, _domain: &str) -> Response {
        response::OK
    }

    fn mail(&mut self, _ip: IpAddr, _domain: &str, from: &str) -> Response {
        self.from = from.to_string();
        self.to.clear();
        self.data.clear();
        self.data_size = 0;
        self.size_exceeded = false;
        response::OK
    }

    fn rcpt(&mut self, to: &str) -> Response {
        // Enforce recipient limit
        if self.to.len() >= MAX_RECIPIENTS_PER_MESSAGE {
            return Response::custom(452, "Too many recipients".to_string());
        }

        // Validate recipient domain against known domains (prevents open relay).
        // We accept addresses on known domains; per-address validation happens async.
        let domain = match to.split('@').nth(1) {
            Some(d) => d.to_lowercase(),
            None => return Response::custom(550, "Invalid recipient address".to_string()),
        };

        // RwLock::try_read avoids blocking the sync SMTP handler.
        // If lock is contended (domain refresh in progress), accept optimistically.
        let domain_known = match self.known_domains.try_read() {
            Ok(domains) => domains.contains(&domain),
            Err(_) => true, // Accept if lock contended; async processing will reject unknown
        };

        if !domain_known {
            return Response::custom(550, format!("Relay access denied for domain {}", domain));
        }

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
        self.data_size = 0;
        self.size_exceeded = false;
        response::OK
    }

    fn data(&mut self, buf: &[u8]) -> io::Result<()> {
        self.data_size += buf.len();
        if self.data_size > self.max_message_size {
            // Stop accumulating but don't error yet -- report in data_end
            self.size_exceeded = true;
            self.data.clear(); // Free memory
            return Ok(());
        }
        self.data.extend_from_slice(buf);
        Ok(())
    }

    fn data_end(&mut self) -> Response {
        if self.size_exceeded {
            return Response::custom(552, "Message size exceeds maximum".to_string());
        }

        let msg = ReceivedMessage {
            from: self.from.clone(),
            to: self.to.clone(),
            data: std::mem::take(&mut self.data),
        };

        match self.tx.send(msg) {
            Ok(_) => response::OK,
            Err(_) => {
                // Channel closed -- server shutting down
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

    // Load initial domain cache
    let domains = state.db.list_known_domains().await.unwrap_or_default();
    let known_domains = Arc::new(RwLock::new(domains));

    let handler = InboundHandler {
        tx,
        known_domains: known_domains.clone(),
        max_message_size: state.config.max_message_size,
        from: String::new(),
        to: Vec::new(),
        data: Vec::new(),
        data_size: 0,
        size_exceeded: false,
    };

    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_smtp_port);
    tracing::info!("SMTP inbound server starting on {} (STARTTLS: {})", addr,
        if state.config.tls_configured() { "enabled" } else { "disabled" });

    // Spawn background task to refresh domain cache every 60 seconds
    let db_for_cache = state.db.clone();
    let domains_handle = known_domains.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            match db_for_cache.list_known_domains().await {
                Ok(new_domains) => {
                    *domains_handle.write().await = new_domains;
                }
                Err(e) => {
                    tracing::warn!("Failed to refresh domain cache: {}", e);
                }
            }
        }
    });

    // Build TLS config for STARTTLS
    let ssl_config = if let (Some(cert_path), Some(key_path)) = (&state.config.tls_cert_path, &state.config.tls_key_path) {
        let cert_str = cert_path.to_string_lossy().to_string();
        let key_str = key_path.to_string_lossy().to_string();
        if let Some(chain_path) = &state.config.tls_chain_path {
            SslConfig::Trusted {
                cert_path: cert_str,
                key_path: key_str,
                chain_path: chain_path.to_string_lossy().to_string(),
            }
        } else {
            SslConfig::SelfSigned {
                cert_path: cert_str,
                key_path: key_str,
            }
        }
    } else {
        tracing::warn!("SMTP STARTTLS disabled (no TLS cert configured). External MTAs may refuse to deliver.");
        SslConfig::None
    };

    // Spawn the blocking SMTP server in a dedicated thread
    let smtp_addr = addr.clone();
    let mx_name = state.config.mx_hostname.clone();
    let smtp_handle = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let mut server = Server::new(handler);
        server
            .with_name(&mx_name)
            .with_ssl(ssl_config)
            .map_err(|e| anyhow::anyhow!("SMTP TLS config failed: {}", e))?
            .with_addr(&smtp_addr)
            .map_err(|e| anyhow::anyhow!("Invalid SMTP address: {}", e))?;

        server.serve()
            .map_err(|e| anyhow::anyhow!("SMTP inbound server error: {}", e))
    });

    // Process received messages asynchronously
    let process_handle = tokio::spawn(process_inbound_messages(state, rx));

    // Wait for either to finish (normally neither should)
    tokio::select! {
        res = smtp_handle => {
            res??;
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

    // Use UUID for temp filename (prevents path injection from message-id)
    let file_id = uuid::Uuid::new_v4();
    let temp_path = temp_dir.join(format!("{}.eml", file_id));
    tokio::fs::write(&temp_path, raw_data).await?;

    let storage_path = temp_path.to_string_lossy().to_string();

    // Enqueue for Path A pickup. If this fails, clean up the temp file.
    let queue_result = state.db.enqueue_inbound(
        addr.id,
        &message_id,
        from,
        subject.as_deref(),
        raw_data.len() as i64,
        &storage_path,
        state.config.path_a_ttl_secs,
    ).await;

    let queue_id = match queue_result {
        Ok(id) => id,
        Err(e) => {
            // Clean up temp file on DB error
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }
    };

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

    // Send push notification to trigger FxMail to pick up the message
    if let (Some(ref token), Some(ref platform)) = (addr.push_token, addr.push_platform) {
        if let Err(e) = state.push.notify_new_mail(
            token, platform, &queue_id.to_string(), from, subject.as_deref(),
        ).await {
            // Don't fail the mail flow for push errors
            tracing::warn!("Push notification failed for {}: {}", to, e);
        }
    }

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
