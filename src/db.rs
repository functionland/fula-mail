//! Database layer - connects to the shared PostgreSQL instance.
//!
//! Only manages email-specific tables (mail_domains, mail_addresses, mail_inbound_queue,
//! mail_delivery_log). User identity, peer IDs, and auth data are queried from the
//! existing pinning-service/fula-api tables -- never duplicated.

use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

use crate::config::Config;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn connect(config: &Config) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(&config.database_url())
            .await?;

        tracing::info!("Connected to shared PostgreSQL at {}:{}", config.postgres_host, config.postgres_port);
        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<()> {
        // Run email-specific migrations only.
        // Pinning-service migrations are managed by pinning-service's deploy.sh.
        let migration_001 = include_str!("../migrations/postgres/001_mail_schema.sql");
        sqlx::raw_sql(migration_001).execute(&self.pool).await?;

        let migration_002 = include_str!("../migrations/postgres/002_relay_config.sql");
        sqlx::raw_sql(migration_002).execute(&self.pool).await?;

        tracing::info!("Email migrations applied");
        Ok(())
    }

    // ---- Domain operations ----

    pub async fn create_domain(
        &self,
        domain: &str,
        owner_peer_id: &str,
        dkim_selector: &str,
        dkim_private_key: &str,
        dkim_public_key: &str,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO mail_domains (domain, owner_peer_id, dkim_selector, dkim_private_key, dkim_public_key)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id"
        )
        .bind(domain)
        .bind(owner_peer_id)
        .bind(dkim_selector)
        .bind(dkim_private_key)
        .bind(dkim_public_key)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn get_domain_by_name(&self, domain: &str) -> Result<Option<DomainRecord>> {
        let record = sqlx::query_as::<_, DomainRecord>(
            "SELECT id, domain, owner_peer_id, status, mx_verified, spf_verified, dkim_verified, dmarc_verified,
                    dkim_selector, dkim_private_key, dkim_public_key
             FROM mail_domains WHERE domain = $1"
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
    }

    pub async fn update_domain_verification(
        &self,
        domain_id: Uuid,
        mx: bool,
        spf: bool,
        dkim: bool,
        dmarc: bool,
    ) -> Result<()> {
        let status = if mx && spf && dkim { "active" } else { "pending_verification" };

        sqlx::query(
            "UPDATE mail_domains SET mx_verified = $2, spf_verified = $3, dkim_verified = $4,
             dmarc_verified = $5, status = $6, last_verified_at = NOW() WHERE id = $1"
        )
        .bind(domain_id)
        .bind(mx)
        .bind(spf)
        .bind(dkim)
        .bind(dmarc)
        .bind(status)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ---- Address operations ----

    pub async fn create_address(
        &self,
        email: &str,
        domain_id: Uuid,
        owner_peer_id: &str,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO mail_addresses (email, domain_id, owner_peer_id)
             VALUES ($1, $2, $3) RETURNING id"
        )
        .bind(email)
        .bind(domain_id)
        .bind(owner_peer_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn get_address_by_email(&self, email: &str) -> Result<Option<AddressRecord>> {
        let record = sqlx::query_as::<_, AddressRecord>(
            "SELECT a.id, a.email, a.domain_id, a.owner_peer_id, a.push_token, a.push_platform,
                    a.relay_provider, a.relay_api_key, a.relay_smtp_host, a.relay_smtp_port,
                    a.relay_smtp_user, a.relay_mailgun_domain,
                    d.domain, d.dkim_private_key, d.dkim_selector, d.status as domain_status
             FROM mail_addresses a
             JOIN mail_domains d ON d.id = a.domain_id
             WHERE a.email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
    }

    pub async fn update_push_token(
        &self,
        address_id: Uuid,
        token: &str,
        platform: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE mail_addresses SET push_token = $2, push_platform = $3 WHERE id = $1"
        )
        .bind(address_id)
        .bind(token)
        .bind(platform)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ---- Relay config (BYOK: SendGrid, Mailgun, SMTP) ----

    pub async fn set_relay_config(&self, email: &str, config: &RelayConfig) -> Result<()> {
        match config {
            RelayConfig::SendGrid { api_key } => {
                sqlx::query(
                    "UPDATE mail_addresses SET relay_provider = 'sendgrid', relay_api_key = $2,
                     relay_smtp_host = NULL, relay_smtp_port = NULL, relay_smtp_user = NULL, relay_mailgun_domain = NULL
                     WHERE email = $1"
                )
                .bind(email)
                .bind(api_key)
                .execute(&self.pool)
                .await?;
            }
            RelayConfig::Mailgun { api_key, domain } => {
                sqlx::query(
                    "UPDATE mail_addresses SET relay_provider = 'mailgun', relay_api_key = $2,
                     relay_mailgun_domain = $3,
                     relay_smtp_host = NULL, relay_smtp_port = NULL, relay_smtp_user = NULL
                     WHERE email = $1"
                )
                .bind(email)
                .bind(api_key)
                .bind(domain)
                .execute(&self.pool)
                .await?;
            }
            RelayConfig::Smtp { host, port, username, password } => {
                sqlx::query(
                    "UPDATE mail_addresses SET relay_provider = 'smtp', relay_api_key = $2,
                     relay_smtp_host = $3, relay_smtp_port = $4, relay_smtp_user = $5,
                     relay_mailgun_domain = NULL
                     WHERE email = $1"
                )
                .bind(email)
                .bind(password)
                .bind(host)
                .bind(*port as i32)
                .bind(username)
                .execute(&self.pool)
                .await?;
            }
        }

        Ok(())
    }

    pub async fn clear_relay_config(&self, email: &str) -> Result<()> {
        sqlx::query(
            "UPDATE mail_addresses SET relay_provider = NULL, relay_api_key = NULL,
             relay_smtp_host = NULL, relay_smtp_port = NULL, relay_smtp_user = NULL, relay_mailgun_domain = NULL
             WHERE email = $1"
        )
        .bind(email)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ---- Inbound queue (Path A) ----

    pub async fn enqueue_inbound(
        &self,
        address_id: Uuid,
        message_id: &str,
        sender: &str,
        subject: Option<&str>,
        raw_size: i32,
        storage_path: &str,
        ttl_secs: u64,
    ) -> Result<Uuid> {
        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO mail_inbound_queue (address_id, message_id, sender, subject, raw_size, storage_path, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW() + make_interval(secs => $7))
             RETURNING id"
        )
        .bind(address_id)
        .bind(message_id)
        .bind(sender)
        .bind(subject)
        .bind(raw_size)
        .bind(storage_path)
        .bind(ttl_secs as f64)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    pub async fn mark_picked_up(&self, queue_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE mail_inbound_queue SET status = 'picked_up', picked_up_at = NOW() WHERE id = $1"
        )
        .bind(queue_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_pending_for_peer(&self, peer_id: &str) -> Result<Vec<PendingMailRecord>> {
        let records = sqlx::query_as::<_, PendingMailRecord>(
            "SELECT q.id, q.message_id, q.sender, q.subject, q.raw_size, q.created_at
             FROM mail_inbound_queue q
             JOIN mail_addresses a ON a.id = q.address_id
             WHERE a.owner_peer_id = $1 AND q.status = 'pending'
             ORDER BY q.created_at DESC"
        )
        .bind(peer_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    pub async fn get_queue_entry(&self, queue_id: Uuid) -> Result<Option<QueueEntryRecord>> {
        let record = sqlx::query_as::<_, QueueEntryRecord>(
            "SELECT id, address_id, message_id, storage_path, status
             FROM mail_inbound_queue WHERE id = $1"
        )
        .bind(queue_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
    }

    pub async fn get_expired_pending(&self) -> Result<Vec<InboundQueueRecord>> {
        let records = sqlx::query_as::<_, InboundQueueRecord>(
            "SELECT q.id, q.address_id, q.message_id, q.storage_path, a.owner_peer_id
             FROM mail_inbound_queue q
             JOIN mail_addresses a ON a.id = q.address_id
             WHERE q.status = 'pending' AND q.expires_at < NOW()"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    pub async fn mark_fallback_encrypted(&self, queue_id: Uuid, cid: &str) -> Result<()> {
        sqlx::query(
            "UPDATE mail_inbound_queue SET status = 'fallback_encrypted', fallback_cid = $2 WHERE id = $1"
        )
        .bind(queue_id)
        .bind(cid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ---- Delivery log ----

    pub async fn log_delivery(
        &self,
        direction: &str,
        address_id: Option<Uuid>,
        message_id: Option<&str>,
        sender: &str,
        recipient: &str,
        status: &str,
        smtp_code: Option<i32>,
        smtp_response: Option<&str>,
        encrypted_cid: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO mail_delivery_log (direction, address_id, message_id, sender, recipient, status, smtp_code, smtp_response, encrypted_cid)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind(direction)
        .bind(address_id)
        .bind(message_id)
        .bind(sender)
        .bind(recipient)
        .bind(status)
        .bind(smtp_code)
        .bind(smtp_response)
        .bind(encrypted_cid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[derive(sqlx::FromRow, Debug)]
pub struct DomainRecord {
    pub id: Uuid,
    pub domain: String,
    pub owner_peer_id: String,
    pub status: String,
    pub mx_verified: bool,
    pub spf_verified: bool,
    pub dkim_verified: bool,
    pub dmarc_verified: bool,
    pub dkim_selector: String,
    pub dkim_private_key: String,
    pub dkim_public_key: String,
}

#[derive(sqlx::FromRow, Debug)]
pub struct AddressRecord {
    pub id: Uuid,
    pub email: String,
    pub domain_id: Uuid,
    pub owner_peer_id: String,
    pub push_token: Option<String>,
    pub push_platform: Option<String>,
    // Relay config (BYOK)
    pub relay_provider: Option<String>,
    pub relay_api_key: Option<String>,
    pub relay_smtp_host: Option<String>,
    pub relay_smtp_port: Option<i32>,
    pub relay_smtp_user: Option<String>,
    pub relay_mailgun_domain: Option<String>,
    // Joined from domain
    pub domain: String,
    pub dkim_private_key: String,
    pub dkim_selector: String,
    pub domain_status: String,
}

impl AddressRecord {
    /// Build a RelayConfig from the stored fields, if a relay is configured.
    pub fn relay_config(&self) -> Option<RelayConfig> {
        match self.relay_provider.as_deref() {
            Some("sendgrid") => Some(RelayConfig::SendGrid {
                api_key: self.relay_api_key.clone()?,
            }),
            Some("mailgun") => Some(RelayConfig::Mailgun {
                api_key: self.relay_api_key.clone()?,
                domain: self.relay_mailgun_domain.clone()?,
            }),
            Some("smtp") => Some(RelayConfig::Smtp {
                host: self.relay_smtp_host.clone()?,
                port: self.relay_smtp_port.unwrap_or(587) as u16,
                username: self.relay_smtp_user.clone().unwrap_or_default(),
                password: self.relay_api_key.clone()?,
            }),
            _ => None,
        }
    }
}

/// User's outbound relay configuration.
/// Users bring their own API key — no IP warming needed for the gateway.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum RelayConfig {
    SendGrid { api_key: String },
    Mailgun { api_key: String, domain: String },
    Smtp { host: String, port: u16, username: String, password: String },
}

#[derive(sqlx::FromRow, Debug)]
pub struct PendingMailRecord {
    pub id: Uuid,
    pub message_id: String,
    pub sender: String,
    pub subject: Option<String>,
    pub raw_size: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct QueueEntryRecord {
    pub id: Uuid,
    pub address_id: Uuid,
    pub message_id: String,
    pub storage_path: String,
    pub status: String,
}

#[derive(sqlx::FromRow, Debug)]
pub struct InboundQueueRecord {
    pub id: Uuid,
    pub address_id: Uuid,
    pub message_id: String,
    pub storage_path: String,
    pub owner_peer_id: String,
}
