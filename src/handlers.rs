//! HTTP API handlers for domain management, Path A pickup, and outbound submission.

use std::sync::Arc;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::AuthenticatedUser, dns, error::MailError, server::AppState};

// ---- Health ----

/// Deep readiness probe: checks DB connectivity.
/// Returns 200 if healthy, 503 if any dependency is down.
pub async fn health(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Check DB connectivity
    let db_ok = state.db.health_check().await;

    if db_ok {
        Ok(Json(serde_json::json!({
            "status": "ok",
            "db": "connected",
        })))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

// ---- Domain management ----

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
}

#[derive(Serialize)]
pub struct CreateDomainResponse {
    pub id: Uuid,
    pub domain: String,
    pub dns_records: DnsRecords,
}

#[derive(Serialize)]
pub struct DnsRecords {
    pub mx: String,
    pub spf: String,
    pub dkim: String,
    pub dmarc: String,
}

pub async fn create_domain(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<CreateDomainResponse>, MailError> {
    // Use the authenticated user's peer_id as domain owner
    let owner_peer_id = &user.peer_id;

    // Validate peer ID format
    crate::crypto::ed25519_pubkey_from_peer_id(owner_peer_id)
        .map_err(|e| MailError::InvalidPeerId(e.to_string()))?;

    // Generate DKIM keypair for this domain
    let (dkim_private, dkim_public) = dns::generate_dkim_keypair()?;

    let domain_id = state.db.create_domain(
        &req.domain,
        owner_peer_id,
        "fula",
        &dkim_private,
        &dkim_public,
    ).await.map_err(|e| MailError::Internal(e))?;

    let dns_records = dns::required_dns_records(&req.domain, &state.config.mx_hostname, &dkim_public, "fula");

    Ok(Json(CreateDomainResponse {
        id: domain_id,
        domain: req.domain,
        dns_records,
    }))
}

pub async fn get_domain(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, MailError> {
    let record = state.db.get_domain_by_name(&domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain.clone()))?;

    // Only domain owner can view domain details
    if record.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the domain owner".to_string()));
    }

    // Always check DNS live -- no cached flags
    let verification = dns::verify_domain_dns(&domain, &state.config.mx_hostname, &record.dkim_public_key, &record.dkim_selector).await
        .unwrap_or(dns::DnsVerification { mx: false, spf: false, dkim: false, dmarc: false });

    let live_status = if verification.mx && verification.spf && verification.dkim { "active" } else { "pending_verification" };

    // Update stored status if it changed (so SMTP inbound can fast-check without DNS)
    if record.status != live_status {
        let _ = state.db.update_domain_verification(
            record.id, verification.mx, verification.spf, verification.dkim, verification.dmarc,
        ).await;
    }

    Ok(Json(serde_json::json!({
        "id": record.id,
        "domain": record.domain,
        "status": live_status,
        "mx_verified": verification.mx,
        "spf_verified": verification.spf,
        "dkim_verified": verification.dkim,
        "dmarc_verified": verification.dmarc,
    })))
}

pub async fn verify_domain(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, MailError> {
    let record = state.db.get_domain_by_name(&domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain.clone()))?;

    if record.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the domain owner".to_string()));
    }

    // Always real-time DNS check
    let verification = dns::verify_domain_dns(&domain, &state.config.mx_hostname, &record.dkim_public_key, &record.dkim_selector).await
        .map_err(|e| MailError::DnsError(e.to_string()))?;

    let status = if verification.mx && verification.spf && verification.dkim { "active" } else { "pending_verification" };

    // Persist the result so SMTP inbound can fast-check domain_status without DNS lookup
    state.db.update_domain_verification(
        record.id,
        verification.mx,
        verification.spf,
        verification.dkim,
        verification.dmarc,
    ).await.map_err(|e| MailError::Internal(e))?;

    Ok(Json(serde_json::json!({
        "domain": domain,
        "mx_verified": verification.mx,
        "spf_verified": verification.spf,
        "dkim_verified": verification.dkim,
        "dmarc_verified": verification.dmarc,
        "status": status,
    })))
}

pub async fn get_dns_records(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(domain): Path<String>,
) -> Result<Json<DnsRecords>, MailError> {
    let record = state.db.get_domain_by_name(&domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain.clone()))?;

    if record.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the domain owner".to_string()));
    }

    let records = dns::required_dns_records(&domain, &state.config.mx_hostname, &record.dkim_public_key, &record.dkim_selector);
    Ok(Json(records))
}

// ---- Address management ----

#[derive(Deserialize)]
pub struct CreateAddressRequest {
    pub email: String,
}

pub async fn create_address(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<CreateAddressRequest>,
) -> Result<Json<serde_json::Value>, MailError> {
    // Validate email format: must have exactly one @
    let parts: Vec<&str> = req.email.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(MailError::InvalidInput("Invalid email format".to_string()));
    }
    let domain = parts[1];

    let domain_record = state.db.get_domain_by_name(domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain.to_string()))?;

    // Verify the authenticated user owns this domain
    if domain_record.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the domain owner".to_string()));
    }

    if domain_record.status != "active" {
        return Err(MailError::DomainNotVerified(domain.to_string()));
    }

    let id = state.db.create_address(&req.email, domain_record.id, &user.peer_id).await
        .map_err(|e| {
            if e.to_string().contains("duplicate") || e.to_string().contains("unique") {
                MailError::AddressExists(req.email.clone())
            } else {
                MailError::Internal(e)
            }
        })?;

    Ok(Json(serde_json::json!({
        "id": id,
        "email": req.email,
    })))
}

// ---- Path A: client pickup ----
// FxMail authenticates with JWT (same as FxFiles), fetches raw mail,
// encrypts locally with own key, stores via S3, then ACKs.

pub async fn list_pending_mail(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, MailError> {
    let pending = state.db.list_pending_for_peer(&user.peer_id).await
        .map_err(|e| MailError::Internal(e))?;

    let items: Vec<serde_json::Value> = pending.iter().map(|p| {
        serde_json::json!({
            "queue_id": p.id,
            "message_id": p.message_id,
            "sender": p.sender,
            "subject": p.subject,
            "size": p.raw_size,
            "received_at": p.created_at,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "pending": items })))
}

pub async fn get_raw_mail(
    State(state): State<Arc<AppState>>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(queue_id): Path<Uuid>,
) -> Result<axum::response::Response, MailError> {
    // Atomically claim the entry (TOCTOU fix: UPDATE...WHERE status='pending' RETURNING)
    let entry = state.db.claim_queue_entry(queue_id).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::QueueNotFound(format!("Entry {} not found or already picked up", queue_id)))?;

    let data = tokio::fs::read(&entry.storage_path).await
        .map_err(|e| MailError::Internal(anyhow::anyhow!("Cannot read temp file: {}", e)))?;

    axum::response::Response::builder()
        .header("Content-Type", "message/rfc822")
        .header("X-Queue-Id", queue_id.to_string())
        .body(axum::body::Body::from(data))
        .map_err(|e| MailError::Internal(anyhow::anyhow!("Response build failed: {}", e)))
}

pub async fn ack_mail_pickup(
    State(state): State<Arc<AppState>>,
    Extension(_user): Extension<AuthenticatedUser>,
    Path(queue_id): Path<Uuid>,
) -> Result<StatusCode, MailError> {
    let entry = state.db.get_queue_entry(queue_id).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::QueueNotFound(queue_id.to_string()))?;

    // Entry should already be 'picked_up' from get_raw_mail's claim_queue_entry.
    // Delete temp file.
    let _ = tokio::fs::remove_file(&entry.storage_path).await;

    tracing::info!("Path A: client acknowledged queue_id={}", queue_id);
    Ok(StatusCode::OK)
}

// ---- Push token ----

#[derive(Deserialize)]
pub struct PushTokenRequest {
    pub email: String,
    pub token: String,
    pub platform: String,
}

pub async fn register_push_token(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<PushTokenRequest>,
) -> Result<StatusCode, MailError> {
    let addr = state.db.get_address_by_email(&req.email).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::AddressNotFound(req.email.clone()))?;

    // Only the address owner can register push tokens
    if addr.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the address owner".to_string()));
    }

    state.db.update_push_token(addr.id, &req.token, &req.platform).await
        .map_err(|e| MailError::Internal(e))?;

    Ok(StatusCode::OK)
}

// ---- Relay config (BYOK: SendGrid, Mailgun, SMTP) ----

pub async fn set_relay_config(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<SetRelayConfigRequest>,
) -> Result<Json<serde_json::Value>, MailError> {
    // Verify address exists and user owns it
    let addr = state.db.get_address_by_email(&req.email).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::AddressNotFound(req.email.clone()))?;

    if addr.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the address owner".to_string()));
    }

    state.db.set_relay_config(&req.email, &req.relay).await
        .map_err(|e| MailError::Internal(e))?;

    // Log provider name only -- never log the config struct (contains secrets)
    tracing::info!("Relay config set for {}: provider={}", req.email, req.relay.provider_name());
    Ok(Json(serde_json::json!({
        "email": req.email,
        "provider": req.relay.provider_name(),
        "status": "configured",
    })))
}

pub async fn get_relay_config(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(email): Path<String>,
) -> Result<Json<serde_json::Value>, MailError> {
    let addr = state.db.get_address_by_email(&email).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::AddressNotFound(email.clone()))?;

    if addr.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the address owner".to_string()));
    }

    let relay = addr.relay_config();
    Ok(Json(serde_json::json!({
        "email": email,
        "configured": relay.is_some(),
        "provider": addr.relay_provider,
    })))
}

pub async fn delete_relay_config(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Path(email): Path<String>,
) -> Result<StatusCode, MailError> {
    let addr = state.db.get_address_by_email(&email).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::AddressNotFound(email.clone()))?;

    if addr.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the address owner".to_string()));
    }

    state.db.clear_relay_config(&email).await
        .map_err(|e| MailError::Internal(e))?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct SetRelayConfigRequest {
    pub email: String,
    #[serde(flatten)]
    pub relay: crate::db::RelayConfig,
}

// ---- Outbound ----

#[derive(Deserialize)]
pub struct OutboundRequest {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
    pub content_type: Option<String>,
}

pub async fn submit_outbound(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(req): Json<OutboundRequest>,
) -> Result<Json<serde_json::Value>, MailError> {
    // Verify the sender address belongs to the authenticated user
    let addr = state.db.get_address_by_email(&req.from).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::AddressNotFound(req.from.clone()))?;

    if addr.owner_peer_id != user.peer_id {
        return Err(MailError::Forbidden("Not the sender address owner".to_string()));
    }

    // Enqueue for delivery (worker picks it up with retry logic)
    let queue_id = crate::outbound::enqueue_outbound(&state.db, &req, addr.id).await
        .map_err(|e| MailError::Internal(e))?;

    Ok(Json(serde_json::json!({
        "status": "queued",
        "queue_id": queue_id,
    })))
}
