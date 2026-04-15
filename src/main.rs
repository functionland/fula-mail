//! Fula Mail - Decentralized Email Gateway
//!
//! SMTP gateway that bridges standard email to Fula's encrypted decentralized storage.
//! - Inbound: SMTP receive -> encrypt (Path A: client-side, Path B: gateway fallback) -> pin to IPFS
//! - Outbound: client submits -> DKIM sign -> SMTP relay
//! - Standard clients: IMAP/JMAP access (Path B encryption)
//! - NO private key custody: gateway only uses public keys from on-chain peer IDs

mod auth;
mod config;
mod crypto;
mod db;
mod dns;
mod error;
mod handlers;
mod inbound;
mod outbound;
mod pinning;
mod push;
mod secrets;
mod server;
mod smtp;

use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "fula-mail", about = "Fula Mail - Decentralized Email Gateway")]
struct Cli {
    /// Path to .env configuration file
    #[arg(short, long, default_value = ".env")]
    config: String,

    /// Run database migrations and exit
    #[arg(long)]
    migrate: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Load and validate configuration
    let config = config::Config::from_env(&cli.config)?;
    config.validate()?;
    tracing::info!("Fula Mail starting on {}:{}", config.mail_host, config.mail_http_port);

    // Connect to shared PostgreSQL (same instance as pinning-service/fula-api)
    let db = db::Database::connect(&config).await?;

    if cli.migrate {
        tracing::info!("Running migrations...");
        db.run_migrations().await?;
        tracing::info!("Migrations complete");
        return Ok(());
    }

    // Run migrations on startup
    db.run_migrations().await?;

    // M8: Recover entries stuck in transient states from unclean shutdown
    let stuck_outbound = db.recover_stuck_outbound().await.unwrap_or(0);
    let stuck_inbound = db.recover_stuck_inbound().await.unwrap_or(0);
    if stuck_outbound > 0 || stuck_inbound > 0 {
        tracing::info!("Recovered {} stuck outbound and {} stuck inbound entries from previous shutdown",
            stuck_outbound, stuck_inbound);
    }

    // H5: Ensure temp storage directory exists
    tokio::fs::create_dir_all(&config.temp_storage_path).await?;

    // Initialize pinning service client
    let pinning = pinning::PinningClient::new(&config);

    // Initialize push notification client
    let push = push::PushClient::new(config.fcm_key_path.as_deref());

    // Build application state
    let state = server::AppState::new(config.clone(), db, pinning, push);

    // M8: Graceful shutdown with drain period
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let shutdown_token_clone = shutdown_token.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutdown signal received, draining in-flight work (5s)...");
        shutdown_token_clone.cancel();
    });

    // H9: Spawn queue cleanup worker
    let cleanup_state = state.clone();
    let cleanup_token = shutdown_token.clone();
    tokio::spawn(async move {
        run_cleanup_worker(cleanup_state, cleanup_token).await;
    });

    tokio::select! {
        result = async {
            tokio::try_join!(
                // HTTP API server (management, JMAP, Path A pickup)
                server::run_http(state.clone()),
                // SMTP inbound server
                smtp::run_smtp_inbound(state.clone()),
                // Inbound queue expiry worker (Path A -> Path B fallback)
                inbound::run_expiry_worker(state.clone()),
                // Outbound delivery worker (retry queue)
                outbound::run_outbound_worker(state.clone()),
            )
        } => {
            result?;
        }
        _ = shutdown_token.cancelled() => {
            // M8: Allow 5s for in-flight work to complete
            tracing::info!("Shutting down gracefully (5s drain)...");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            tracing::info!("Shutdown complete");
        }
    }

    Ok(())
}

/// H9: Background worker that cleans up old queue entries and delivery logs.
/// Runs once per hour.
async fn run_cleanup_worker(
    state: std::sync::Arc<server::AppState>,
    token: tokio_util::sync::CancellationToken,
) {
    let retention_days = state.config.queue_retention_days;
    tracing::info!("Queue cleanup worker started (retention: {} days)", retention_days);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(3600)) => {}
            _ = token.cancelled() => {
                tracing::info!("Cleanup worker shutting down");
                return;
            }
        }

        match state.db.cleanup_old_queue_entries(retention_days).await {
            Ok((inbound, outbound, logs)) => {
                if inbound > 0 || outbound > 0 || logs > 0 {
                    tracing::info!("Cleaned up {} inbound, {} outbound, {} log entries",
                        inbound, outbound, logs);
                }
            }
            Err(e) => {
                tracing::error!("Queue cleanup error: {}", e);
            }
        }
    }
}
