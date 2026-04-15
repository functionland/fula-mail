//! SMTP server: inbound (port 25).
//!
//! Uses mailin-embedded for the SMTP protocol layer. Received messages are sent
//! through a channel to the async processing pipeline (Path A queue or Path B fallback).

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use mailin_embedded::{response, Handler, Response, Server, SslConfig};
use tokio::sync::{mpsc, RwLock, Mutex};

use crate::server::AppState;

/// Maximum recipients per SMTP session (prevents abuse).
const MAX_RECIPIENTS_PER_MESSAGE: usize = 100;

/// A complete message received via SMTP, ready for processing.
pub struct ReceivedMessage {
    pub from: String,
    pub to: Vec<String>,
    pub data: Vec<u8>,
    /// Sender's IP address (for SPF verification).
    pub sender_ip: IpAddr,
    /// EHLO domain from the sending MTA.
    pub ehlo_domain: String,
}

/// Per-IP connection counter for SMTP rate limiting (H3).
#[derive(Clone)]
struct ConnectionTracker {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

impl ConnectionTracker {
    fn new(max_per_ip: usize) -> Self {
        Self {
            counts: Arc::new(Mutex::new(HashMap::new())),
            max_per_ip,
        }
    }
}

/// SMTP handler for inbound mail (port 25).
///
/// Each SMTP connection gets a clone of this handler. Per-connection state
/// (from, to, data buffer) is accumulated during the session, then the
/// complete message is sent through the channel on data_end().
#[derive(Clone)]
struct InboundHandler {
    tx: mpsc::Sender<ReceivedMessage>,
    /// Known domains for recipient validation (refreshed periodically).
    known_domains: Arc<RwLock<HashSet<String>>>,
    /// Maximum message size in bytes.
    max_message_size: usize,
    /// Per-IP connection tracking (H3).
    conn_tracker: ConnectionTracker,
    // Per-connection state (reset on each clone / new connection)
    from: String,
    to: Vec<String>,
    data: Vec<u8>,
    data_size: usize,
    size_exceeded: bool,
    /// Sender's IP (for SPF verification and rate limiting).
    sender_ip: Option<IpAddr>,
    /// EHLO domain (for logging).
    ehlo_domain: String,
}

impl Handler for InboundHandler {
    fn helo(&mut self, ip: IpAddr, domain: &str) -> Response {
        self.sender_ip = Some(ip);
        self.ehlo_domain = domain.to_string();

        // H3: Per-IP connection rate limiting
        if let Ok(mut counts) = self.conn_tracker.counts.try_lock() {
            let count = counts.entry(ip).or_insert(0);
            *count += 1;
            if *count > self.conn_tracker.max_per_ip {
                tracing::warn!("SMTP rate limit exceeded for {}", ip);
                return Response::custom(421, "Too many connections from your IP".to_string());
            }
        }

        // L7: Log EHLO domain for diagnostics
        tracing::debug!("SMTP HELO from {} ({})", ip, domain);
        response::OK
    }

    fn mail(&mut self, ip: IpAddr, _domain: &str, from: &str) -> Response {
        self.sender_ip = Some(ip);
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
            sender_ip: self.sender_ip.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            ehlo_domain: self.ehlo_domain.clone(),
        };

        // H4: Bounded channel — applies backpressure when queue is full
        match self.tx.try_send(msg) {
            Ok(_) => response::OK,
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!("SMTP inbound channel full, rejecting message (backpressure)");
                Response::custom(452, "Too many messages, try again later".to_string())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
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
    // H4: Bounded channel with configurable capacity (backpressure on overload)
    let channel_capacity = state.config.smtp_channel_capacity;
    let (tx, rx) = mpsc::channel::<ReceivedMessage>(channel_capacity);

    // Load initial domain cache
    let domains = state.db.list_known_domains().await.unwrap_or_default();
    let known_domains = Arc::new(RwLock::new(domains));

    let conn_tracker = ConnectionTracker::new(state.config.smtp_max_connections_per_ip);

    let handler = InboundHandler {
        tx,
        known_domains: known_domains.clone(),
        max_message_size: state.config.max_message_size,
        conn_tracker,
        from: String::new(),
        to: Vec::new(),
        data: Vec::new(),
        data_size: 0,
        size_exceeded: false,
        sender_ip: None,
        ehlo_domain: String::new(),
    };

    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_smtp_port);
    tracing::info!("SMTP inbound server starting on {} (STARTTLS: {}, channel_cap: {}, max_conn/ip: {})",
        addr,
        if state.config.tls_configured() { "enabled" } else { "disabled" },
        channel_capacity,
        state.config.smtp_max_connections_per_ip);

    // Spawn background task to refresh domain cache (M10: configurable interval)
    let db_for_cache = state.db.clone();
    let domains_handle = known_domains.clone();
    let cache_refresh_secs = state.config.domain_cache_refresh_secs;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(cache_refresh_secs)).await;
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
    mut rx: mpsc::Receiver<ReceivedMessage>,
) -> anyhow::Result<()> {
    // H5: Use configurable persistent path instead of /tmp
    let temp_dir = state.config.temp_storage_path.clone();
    tokio::fs::create_dir_all(&temp_dir).await?;
    tracing::info!("Inbound temp storage: {:?}", temp_dir);

    while let Some(msg) = rx.recv().await {
        // C4: Verify sender authentication (SPF/DKIM/DMARC) before processing
        let auth_result = verify_sender_auth(&msg).await;
        if let Some(ref result) = auth_result {
            tracing::info!("Mail auth from {}: SPF={}, DKIM={}, DMARC={}",
                msg.from,
                if result.spf_pass { "pass" } else { "fail" },
                if result.dkim_pass { "pass" } else { "fail" },
                if result.dmarc_pass { "pass" } else { "fail" });
        }

        for recipient in &msg.to {
            if let Err(e) = process_single_recipient(
                &state, &msg.from, recipient, &msg.data, &temp_dir,
                auth_result.as_ref(),
            ).await {
                tracing::error!("Failed to process mail for {}: {}", recipient, e);
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

/// Result of sender authentication checks (C4).
struct AuthResult {
    spf_pass: bool,
    dkim_pass: bool,
    dmarc_pass: bool,
    header: String,
}

/// Verify SPF, DKIM, and DMARC for an inbound message (C4).
async fn verify_sender_auth(msg: &ReceivedMessage) -> Option<AuthResult> {
    use mail_auth::{AuthenticatedMessage, Resolver, SpfResult, DkimResult, DmarcResult};

    let resolver = match Resolver::new_system_conf() {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to create DNS resolver for mail auth: {}", e);
            return None;
        }
    };

    let mail_from_domain = msg.from.split('@').nth(1).unwrap_or(&msg.ehlo_domain);

    // SPF verification: check if sending IP is authorized for the sender's domain
    let spf_output = resolver.verify_spf(
        msg.sender_ip,
        &msg.ehlo_domain,
        mail_from_domain,
        &msg.from,
    ).await;
    let spf_pass = matches!(spf_output.result(), SpfResult::Pass);

    // Parse message for DKIM/DMARC verification
    let authenticated_msg = match AuthenticatedMessage::parse(&msg.data) {
        Some(m) => m,
        None => {
            tracing::warn!("Failed to parse message for DKIM/DMARC verification");
            let header = format!(
                "Authentication-Results: fula-mail; spf={} smtp.mailfrom={}",
                if spf_pass { "pass" } else { "fail" },
                &msg.from,
            );
            return Some(AuthResult { spf_pass, dkim_pass: false, dmarc_pass: false, header });
        }
    };

    // DKIM verification: check DKIM-Signature headers
    let dkim_output = resolver.verify_dkim(&authenticated_msg).await;
    let dkim_pass = dkim_output.iter().any(|r| r.result() == &DkimResult::Pass);

    // DMARC verification: check alignment between From header and SPF/DKIM results
    let dmarc_output = resolver.verify_dmarc(
        &authenticated_msg,
        &dkim_output,
        mail_from_domain,
        &spf_output,
    ).await;
    let dmarc_pass = matches!(dmarc_output.dkim_result(), DmarcResult::Pass)
        || matches!(dmarc_output.spf_result(), DmarcResult::Pass);

    let from_domain = msg.from.split('@').nth(1).unwrap_or("unknown");
    let header = format!(
        "Authentication-Results: fula-mail; spf={} smtp.mailfrom={}; dkim={}; dmarc={} header.from={}",
        if spf_pass { "pass" } else { "fail" },
        &msg.from,
        if dkim_pass { "pass" } else { "fail" },
        if dmarc_pass { "pass" } else { "fail" },
        from_domain,
    );

    Some(AuthResult { spf_pass, dkim_pass, dmarc_pass, header })
}

async fn process_single_recipient(
    state: &AppState,
    from: &str,
    to: &str,
    raw_data: &[u8],
    temp_dir: &std::path::Path,
    auth_result: Option<&AuthResult>,
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

    // C4: Prepend Authentication-Results header to stored message
    let stored_data = if let Some(auth) = auth_result {
        let mut augmented = Vec::with_capacity(auth.header.len() + 2 + raw_data.len());
        augmented.extend_from_slice(auth.header.as_bytes());
        augmented.extend_from_slice(b"\r\n");
        augmented.extend_from_slice(raw_data);
        augmented
    } else {
        raw_data.to_vec()
    };

    // Use UUID for temp filename (prevents path injection from message-id)
    let file_id = uuid::Uuid::new_v4();
    let temp_path = temp_dir.join(format!("{}.eml", file_id));
    tokio::fs::write(&temp_path, &stored_data).await?;

    let storage_path = temp_path.to_string_lossy().to_string();

    // Enqueue for Path A pickup. If this fails, clean up the temp file.
    let queue_result = state.db.enqueue_inbound(
        addr.id,
        &message_id,
        from,
        subject.as_deref(),
        stored_data.len() as i64,
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
        match state.push.notify_new_mail(
            token, platform, &queue_id.to_string(), from, subject.as_deref(),
        ).await {
            Ok(crate::push::PushResult::TokenInvalid) => {
                // M6: Clear stale push token so we don't keep trying
                tracing::info!("Clearing stale push token for {}", to);
                let _ = state.db.clear_push_token(addr.id).await;
            }
            Err(e) => {
                // Don't fail the mail flow for push errors
                tracing::warn!("Push notification failed for {}: {}", to, e);
            }
            _ => {}
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
