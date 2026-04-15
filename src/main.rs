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

    // Initialize pinning service client
    let pinning = pinning::PinningClient::new(&config);

    // Initialize push notification client
    let push = push::PushClient::new(config.fcm_key_path.as_deref());

    // Build application state
    let state = server::AppState::new(config.clone(), db, pinning, push);

    // Start all servers concurrently with graceful shutdown
    let shutdown = async {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutdown signal received, draining...");
    };

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
        _ = shutdown => {
            tracing::info!("Shutting down gracefully");
        }
    }

    Ok(())
}
