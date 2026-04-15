//! HTTP API server for management, JMAP, and Path A mail pickup.

use std::sync::Arc;
use axum::{routing::{get, post, put}, Router};
use tokio::net::TcpListener;

use crate::{config::Config, db::Database, handlers, pinning::PinningClient};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub pinning: PinningClient,
}

impl AppState {
    pub fn new(config: Config, db: Database, pinning: PinningClient) -> Arc<Self> {
        Arc::new(Self { config, db, pinning })
    }
}

pub async fn run_http(state: Arc<AppState>) -> anyhow::Result<()> {
    let app = Router::new()
        // Health
        .route("/health", get(handlers::health))

        // Domain management
        .route("/api/v1/domains", post(handlers::create_domain))
        .route("/api/v1/domains/{domain}", get(handlers::get_domain))
        .route("/api/v1/domains/{domain}/verify", post(handlers::verify_domain))
        .route("/api/v1/domains/{domain}/dns-records", get(handlers::get_dns_records))

        // Address management
        .route("/api/v1/addresses", post(handlers::create_address))

        // Path A: client picks up raw mail, encrypts locally
        .route("/api/v1/inbound/pending", get(handlers::list_pending_mail))
        .route("/api/v1/inbound/{queue_id}/raw", get(handlers::get_raw_mail))
        .route("/api/v1/inbound/{queue_id}/ack", post(handlers::ack_mail_pickup))

        // Push notification token registration
        .route("/api/v1/push-token", put(handlers::register_push_token))

        // Relay config (BYOK: user provides their own SendGrid/Mailgun/SMTP credentials)
        .route("/api/v1/relay", post(handlers::set_relay_config))
        .route("/api/v1/relay/{email}", get(handlers::get_relay_config).delete(handlers::delete_relay_config))

        // Outbound: client submits plaintext for SMTP relay
        .route("/api/v1/outbound/send", post(handlers::submit_outbound))

        .with_state(state.clone());

    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_http_port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("HTTP API listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
