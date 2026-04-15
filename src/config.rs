use anyhow::Result;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    // Server
    pub mail_host: String,
    pub mail_http_port: u16,
    pub mail_smtp_port: u16,
    pub mail_submission_port: u16,
    pub mail_imap_port: u16,

    // Database (shared PostgreSQL)
    pub postgres_host: String,
    pub postgres_port: u16,
    pub postgres_db: String,
    pub postgres_user: String,
    pub postgres_password: String,

    // Pinning service
    pub pinning_service_url: String,
    pub pinning_system_key: String,

    // TLS
    pub tls_cert_path: Option<PathBuf>,
    pub tls_key_path: Option<PathBuf>,
    pub tls_chain_path: Option<PathBuf>,

    // Auth (same JWT as FxFiles/pinning-service)
    pub jwt_secret: String,

    // MX hostname
    pub mx_hostname: String,

    // Push notifications
    pub fcm_key_path: Option<PathBuf>,
    pub apns_cert_path: Option<PathBuf>,

    // Outbound relay (optional, for IP warming)
    pub outbound_relay_host: Option<String>,
    pub outbound_relay_port: Option<u16>,
    pub outbound_relay_user: Option<String>,
    pub outbound_relay_password: Option<String>,

    // Path A settings
    pub path_a_ttl_secs: u64,

    // Limits
    pub max_message_size: usize,
    pub max_retries: i32,

    // Encryption master key for secrets at rest (hex-encoded 32-byte key)
    // Used to encrypt DKIM private keys and relay API keys in the database.
    pub encryption_master_key: Option<String>,
}

impl Config {
    pub fn from_env(dotenv_path: &str) -> Result<Self> {
        let _ = dotenvy::from_filename(dotenv_path);

        Ok(Self {
            mail_host: env_or("MAIL_HOST", "0.0.0.0"),
            mail_http_port: env_or("MAIL_HTTP_PORT", "8080").parse()?,
            mail_smtp_port: env_or("MAIL_SMTP_PORT", "25").parse()?,
            mail_submission_port: env_or("MAIL_SUBMISSION_PORT", "587").parse()?,
            mail_imap_port: env_or("MAIL_IMAP_PORT", "993").parse()?,

            postgres_host: env_or("POSTGRES_HOST", "localhost"),
            postgres_port: env_or("POSTGRES_PORT", "5432").parse()?,
            postgres_db: env_or("POSTGRES_DB", "pinning_service"),
            postgres_user: env_or("POSTGRES_USER", "pinning_user"),
            postgres_password: env_required("POSTGRES_PASSWORD")?,

            pinning_service_url: env_or("PINNING_SERVICE_URL", "http://localhost:6000"),
            pinning_system_key: env_or("PINNING_SYSTEM_KEY", ""),

            tls_cert_path: env_opt("TLS_CERT_PATH").map(PathBuf::from),
            tls_key_path: env_opt("TLS_KEY_PATH").map(PathBuf::from),
            tls_chain_path: env_opt("TLS_CHAIN_PATH").map(PathBuf::from),

            jwt_secret: env_required("JWT_SECRET")?,

            mx_hostname: env_or("MX_HOSTNAME", "mail.fula.net"),

            fcm_key_path: env_opt("FCM_SERVICE_ACCOUNT_KEY").map(PathBuf::from),
            apns_cert_path: env_opt("APNS_CERT_PATH").map(PathBuf::from),

            outbound_relay_host: env_opt("OUTBOUND_RELAY_HOST"),
            outbound_relay_port: env_opt("OUTBOUND_RELAY_PORT")
                .and_then(|p| p.parse().ok()),
            outbound_relay_user: env_opt("OUTBOUND_RELAY_USER"),
            outbound_relay_password: env_opt("OUTBOUND_RELAY_PASSWORD"),

            path_a_ttl_secs: env_or("PATH_A_TTL_SECS", "300").parse()?,

            max_message_size: env_or("MAX_MESSAGE_SIZE", "52428800").parse()?, // 50MB
            max_retries: env_or("MAX_RETRIES", "5").parse()?,

            encryption_master_key: env_opt("ENCRYPTION_MASTER_KEY"),
        })
    }

    /// Returns true if TLS cert and key paths are both configured.
    pub fn tls_configured(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    /// Validate configuration at startup. Catches misconfigurations early
    /// with clear error messages instead of cryptic runtime failures.
    pub fn validate(&self) -> Result<()> {
        // JWT secret must be reasonably strong
        if self.jwt_secret.len() < 16 {
            anyhow::bail!("JWT_SECRET must be at least 16 characters");
        }

        // TLS: if one path is set, both must be set
        if self.tls_cert_path.is_some() != self.tls_key_path.is_some() {
            anyhow::bail!("TLS_CERT_PATH and TLS_KEY_PATH must both be set or both be unset");
        }

        // TLS: verify files exist if paths given
        if let Some(ref path) = self.tls_cert_path {
            if !path.exists() {
                anyhow::bail!("TLS_CERT_PATH does not exist: {:?}", path);
            }
        }
        if let Some(ref path) = self.tls_key_path {
            if !path.exists() {
                anyhow::bail!("TLS_KEY_PATH does not exist: {:?}", path);
            }
        }

        // Encryption master key: if set, must be valid 32-byte hex
        if let Some(ref key) = self.encryption_master_key {
            let bytes = hex::decode(key)
                .map_err(|_| anyhow::anyhow!("ENCRYPTION_MASTER_KEY must be valid hex"))?;
            if bytes.len() != 32 {
                anyhow::bail!("ENCRYPTION_MASTER_KEY must be exactly 32 bytes (64 hex chars), got {}", bytes.len());
            }
        }

        // FCM key file: verify exists if path given
        if let Some(ref path) = self.fcm_key_path {
            if !path.exists() {
                anyhow::bail!("FCM_SERVICE_ACCOUNT_KEY does not exist: {:?}", path);
            }
        }

        // Max message size: sanity check
        if self.max_message_size == 0 {
            anyhow::bail!("MAX_MESSAGE_SIZE must be > 0");
        }

        Ok(())
    }

    pub fn database_url(&self) -> String {
        format!(
            "postgres://{}:{}@{}:{}/{}",
            self.postgres_user,
            self.postgres_password,
            self.postgres_host,
            self.postgres_port,
            self.postgres_db,
        )
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_required(key: &str) -> Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("Required environment variable {} not set", key))
}
