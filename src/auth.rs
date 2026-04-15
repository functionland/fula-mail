//! JWT authentication middleware.
//!
//! Validates Bearer tokens using the same JWT secret as FxFiles/pinning-service.
//! Extracts peer_id from token claims and makes it available to handlers.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::header::AUTHORIZATION,
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

use crate::{error::MailError, server::AppState};

/// JWT claims structure (same as FxFiles/pinning-service).
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject: the user's peer ID
    pub sub: String,
    /// Expiration time (UTC timestamp)
    pub exp: usize,
    /// Issued at (UTC timestamp)
    #[serde(default)]
    pub iat: usize,
}

/// Authenticated user info, inserted into request extensions by the auth middleware.
#[derive(Clone, Debug)]
pub struct AuthenticatedUser {
    pub peer_id: String,
}

/// Axum middleware that validates JWT Bearer tokens.
///
/// Extracts the peer_id from the token and inserts an `AuthenticatedUser`
/// into request extensions. Returns 401 if token is missing or invalid.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, MailError> {
    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(MailError::Unauthorized)?;

    let key = DecodingKey::from_secret(state.config.jwt_secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    // Accept tokens without audience claim (pinning-service doesn't set one)
    validation.validate_aud = false;

    let token_data = decode::<Claims>(token, &key, &validation)
        .map_err(|_| MailError::Unauthorized)?;

    req.extensions_mut().insert(AuthenticatedUser {
        peer_id: token_data.claims.sub,
    });

    Ok(next.run(req).await)
}
