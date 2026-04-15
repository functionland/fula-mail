//! HTTP API server for management, JMAP, and Path A mail pickup.

use std::sync::Arc;
use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post, put},
    Router,
};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor};
use tower_http::cors::{CorsLayer, Any};

use crate::{auth, config::Config, db::Database, handlers, pinning::PinningClient, push::PushClient};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: Database,
    pub pinning: PinningClient,
    pub push: Arc<PushClient>,
}

impl AppState {
    pub fn new(config: Config, db: Database, pinning: PinningClient, push: PushClient) -> Arc<Self> {
        Arc::new(Self { config, db, pinning, push: Arc::new(push) })
    }
}

pub async fn run_http(state: Arc<AppState>) -> anyhow::Result<()> {
    let body_limit = state.config.max_message_size;

    // Rate limiting: 30 requests per second per IP, burst of 60
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(30)
            .burst_size(60)
            .key_extractor(SmartIpKeyExtractor)
            .finish()
            .expect("Failed to build governor config"),
    );

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(handlers::health));

    // Protected routes (JWT auth required)
    let protected_routes = Router::new()
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

        // Apply JWT auth middleware to all protected routes
        .layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware));

    // CORS: allow any origin for now (FxMail clients connect from devices).
    // In production, restrict to specific origins if serving a web client.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers(Any);

    let app = public_routes
        .merge(protected_routes)
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(cors)
        .layer(GovernorLayer::new(governor_conf))
        .with_state(state.clone());

    let addr = format!("{}:{}", state.config.mail_host, state.config.mail_http_port);

    // Use TLS if cert and key are configured, otherwise plain HTTP
    if let (Some(cert_path), Some(key_path)) = (&state.config.tls_cert_path, &state.config.tls_key_path) {
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await?;
        let addr_parsed: std::net::SocketAddr = addr.parse()?;
        tracing::info!("HTTPS API listening on {} (TLS enabled, rate-limited)", addr);
        axum_server::bind_rustls(addr_parsed, tls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        tracing::info!("HTTP API listening on {} (no TLS, rate-limited)", addr);
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;
    }

    Ok(())
}
