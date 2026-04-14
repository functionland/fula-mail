use axum::{http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("Domain not found: {0}")]
    DomainNotFound(String),

    #[error("Domain not verified: {0}")]
    DomainNotVerified(String),

    #[error("Address not found: {0}")]
    AddressNotFound(String),

    #[error("Address already exists: {0}")]
    AddressExists(String),

    #[error("Invalid peer ID: {0}")]
    InvalidPeerId(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Pinning service error: {0}")]
    PinningError(String),

    #[error("DNS verification failed: {0}")]
    DnsError(String),

    #[error("Queue item not found: {0}")]
    QueueNotFound(String),

    #[error("Queue item expired")]
    QueueExpired,

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for MailError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            MailError::DomainNotFound(_) | MailError::AddressNotFound(_) | MailError::QueueNotFound(_) => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            MailError::DomainNotVerified(_) => (StatusCode::PRECONDITION_FAILED, self.to_string()),
            MailError::AddressExists(_) => (StatusCode::CONFLICT, self.to_string()),
            MailError::InvalidPeerId(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            MailError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            MailError::QueueExpired => (StatusCode::GONE, self.to_string()),
            _ => {
                tracing::error!("Internal error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
