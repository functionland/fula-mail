//! HTTP API handlers for domain management, Path A pickup, and outbound submission.

use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{dns, error::MailError, server::AppState};

// ---- Health ----

pub async fn health() -> StatusCode {
    StatusCode::OK
}

// ---- Domain management ----

#[derive(Deserialize)]
pub struct CreateDomainRequest {
    pub domain: String,
    pub owner_peer_id: String,
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
    Json(req): Json<CreateDomainRequest>,
) -> Result<Json<CreateDomainResponse>, MailError> {
    // Validate peer ID format
    crate::crypto::ed25519_pubkey_from_peer_id(&req.owner_peer_id)
        .map_err(|e| MailError::InvalidPeerId(e.to_string()))?;

    // Generate DKIM keypair for this domain
    let (dkim_private, dkim_public) = dns::generate_dkim_keypair()?;

    let domain_id = state.db.create_domain(
        &req.domain,
        &req.owner_peer_id,
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
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, MailError> {
    let record = state.db.get_domain_by_name(&domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain))?;

    Ok(Json(serde_json::json!({
        "id": record.id,
        "domain": record.domain,
        "status": record.status,
        "mx_verified": record.mx_verified,
        "spf_verified": record.spf_verified,
        "dkim_verified": record.dkim_verified,
        "dmarc_verified": record.dmarc_verified,
    })))
}

pub async fn verify_domain(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Result<Json<serde_json::Value>, MailError> {
    let record = state.db.get_domain_by_name(&domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain.clone()))?;

    let verification = dns::verify_domain_dns(&domain, &state.config.mx_hostname, &record.dkim_public_key, &record.dkim_selector).await
        .map_err(|e| MailError::DnsError(e.to_string()))?;

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
        "status": if verification.mx && verification.spf && verification.dkim { "active" } else { "pending_verification" },
    })))
}

pub async fn get_dns_records(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> Result<Json<DnsRecords>, MailError> {
    let record = state.db.get_domain_by_name(&domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain.clone()))?;

    let records = dns::required_dns_records(&domain, &state.config.mx_hostname, &record.dkim_public_key, &record.dkim_selector);
    Ok(Json(records))
}

// ---- Address management ----

#[derive(Deserialize)]
pub struct CreateAddressRequest {
    pub email: String,
    pub peer_id: String,
}

pub async fn create_address(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateAddressRequest>,
) -> Result<Json<serde_json::Value>, MailError> {
    // Extract domain from email
    let domain = req.email
        .split('@')
        .nth(1)
        .ok_or_else(|| MailError::Internal(anyhow::anyhow!("Invalid email format")))?;

    let domain_record = state.db.get_domain_by_name(domain).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::DomainNotFound(domain.to_string()))?;

    if domain_record.status != "active" {
        return Err(MailError::DomainNotVerified(domain.to_string()));
    }

    let id = state.db.create_address(&req.email, domain_record.id, &req.peer_id).await
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

pub async fn list_pending_mail(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, MailError> {
    // TODO: authenticate via JWT, list pending inbound for this user
    Ok(Json(serde_json::json!({ "pending": [] })))
}

pub async fn get_raw_mail(
    State(_state): State<Arc<AppState>>,
    Path(_queue_id): Path<Uuid>,
) -> Result<Vec<u8>, MailError> {
    // TODO: serve raw message bytes for client-side encryption
    Err(MailError::QueueNotFound("not implemented".into()))
}

pub async fn ack_mail_pickup(
    State(_state): State<Arc<AppState>>,
    Path(_queue_id): Path<Uuid>,
) -> Result<StatusCode, MailError> {
    // TODO: mark as picked up, delete temp file
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
    Json(req): Json<PushTokenRequest>,
) -> Result<StatusCode, MailError> {
    let addr = state.db.get_address_by_email(&req.email).await
        .map_err(|e| MailError::Internal(e))?
        .ok_or_else(|| MailError::AddressNotFound(req.email.clone()))?;

    state.db.update_push_token(addr.id, &req.token, &req.platform).await
        .map_err(|e| MailError::Internal(e))?;

    Ok(StatusCode::OK)
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
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<OutboundRequest>,
) -> Result<Json<serde_json::Value>, MailError> {
    // TODO: authenticate via JWT, DKIM sign, SMTP relay
    Ok(Json(serde_json::json!({ "status": "queued" })))
}
