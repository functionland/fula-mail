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

    #[error("Tag not found: {0}")]
    TagNotFound(String),

    #[error("Tag already exists: {0}")]
    TagExists(String),

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

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Message too large")]
    MessageTooLarge,

    #[error("Resource limit: {0}")]
    ResourceLimit(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for MailError {
    fn into_response(self) -> axum::response::Response {
        // Log full details server-side; return generic messages to clients (H10).
        let (status, message) = match &self {
            MailError::DomainNotFound(d) => {
                tracing::warn!("Domain not found: {}", d);
                (StatusCode::NOT_FOUND, "Not found".to_string())
            }
            MailError::AddressNotFound(a) => {
                tracing::warn!("Address not found: {}", a);
                (StatusCode::NOT_FOUND, "Not found".to_string())
            }
            MailError::QueueNotFound(q) => {
                tracing::warn!("Queue entry not found: {}", q);
                (StatusCode::NOT_FOUND, "Not found".to_string())
            }
            MailError::TagNotFound(t) => {
                tracing::warn!("Tag not found: {}", t);
                (StatusCode::NOT_FOUND, "Not found".to_string())
            }
            MailError::TagExists(_) => (StatusCode::CONFLICT, "Tag already exists".to_string()),
            MailError::DomainNotVerified(_) => (StatusCode::PRECONDITION_FAILED, "Domain not verified".to_string()),
            MailError::AddressExists(_) => (StatusCode::CONFLICT, "Address already exists".to_string()),
            MailError::InvalidPeerId(_) => (StatusCode::BAD_REQUEST, "Invalid peer ID".to_string()),
            MailError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            MailError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            MailError::Forbidden(_) => (StatusCode::FORBIDDEN, "Forbidden".to_string()),
            MailError::QueueExpired => (StatusCode::GONE, "Queue entry expired".to_string()),
            MailError::MessageTooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "Message too large".to_string()),
            MailError::ResourceLimit(msg) => (StatusCode::TOO_MANY_REQUESTS, msg.clone()),
            _ => {
                tracing::error!("Internal error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
