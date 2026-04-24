//! Database layer - connects to the shared PostgreSQL instance.
//!
//! Only manages email-specific tables (mail_domains, mail_addresses, mail_inbound_queue,
//! mail_delivery_log). User identity, peer IDs, and auth data are queried from the
//! existing pinning-service/fula-api tables -- never duplicated.

use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

use crate::config::Config;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
    /// Master key for encrypting secrets at rest (DKIM keys, relay API keys).
    /// None = plaintext mode (backwards-compatible).
    master_key: Option<String>,
}

impl Database {
    pub async fn connect(config: &Config) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(config.postgres_max_connections)
            .acquire_timeout(Duration::from_secs(30))
            .idle_timeout(Duration::from_secs(config.postgres_idle_timeout_secs))
            .connect(&config.database_url())
            .await?;

        tracing::info!("Connected to shared PostgreSQL at {}:{} (max_conn={}, idle_timeout={}s)",
            config.postgres_host, config.postgres_port,
            config.postgres_max_connections, config.postgres_idle_timeout_secs);
        if config.encryption_master_key.is_some() {
            tracing::info!("Secret encryption at rest: ENABLED");
        } else {
            tracing::warn!("Secret encryption at rest: DISABLED (set ENCRYPTION_MASTER_KEY to enable)");
        }
        Ok(Self { pool, master_key: config.encryption_master_key.clone() })
    }

    fn encrypt(&self, plaintext: &str) -> Result<String> {
        crate::secrets::encrypt_secret(plaintext, self.master_key.as_deref())
    }

    fn decrypt(&self, stored: &str) -> Result<String> {
        crate::secrets::decrypt_secret(stored, self.master_key.as_deref())
    }

    /// Quick connectivity check for the health endpoint.
    pub async fn health_check(&self) -> bool {
        sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    pub async fn run_migrations(&self) -> Result<()> {
        // Run email-specific migrations only.
        // Pinning-service migrations are managed by pinning-service's deploy.sh.
        let migration_001 = include_str!("../migrations/postgres/001_mail_schema.sql");
        sqlx::raw_sql(migration_001).execute(&self.pool).await?;

        let migration_002 = include_str!("../migrations/postgres/002_relay_config.sql");
        sqlx::raw_sql(migration_002).execute(&self.pool).await?;

        let migration_003 = include_str!("../migrations/postgres/003_hardening.sql");
        sqlx::raw_sql(migration_003).execute(&self.pool).await?;

        let migration_004 = include_str!("../migrations/postgres/004_outbound_queue.sql");
        sqlx::raw_sql(migration_004).execute(&self.pool).await?;

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
        let encrypted_private_key = self.encrypt(dkim_private_key)?;

        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO mail_domains (domain, owner_peer_id, dkim_selector, dkim_private_key, dkim_public_key)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id"
        )
        .bind(domain)
        .bind(owner_peer_id)
        .bind(dkim_selector)
        .bind(&encrypted_private_key)
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

        match record {
            Some(mut r) => {
                r.dkim_private_key = self.decrypt(&r.dkim_private_key)?;
                Ok(Some(r))
            }
            None => Ok(None),
        }
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

    /// Load all known domain names for SMTP recipient validation cache.
    pub async fn list_known_domains(&self) -> Result<HashSet<String>> {
        let rows = sqlx::query_scalar::<_, String>(
            "SELECT domain FROM mail_domains WHERE status IN ('active', 'pending_verification')"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().collect())
    }

    /// Count domains owned by a peer (for H7 resource limits).
    pub async fn count_domains_for_peer(&self, peer_id: &str) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM mail_domains WHERE owner_peer_id = $1"
        )
        .bind(peer_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

    // ---- Address operations ----

    /// Count addresses under a domain (for H7 resource limits).
    pub async fn count_addresses_for_domain(&self, domain_id: Uuid) -> Result<i64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM mail_addresses WHERE domain_id = $1"
        )
        .bind(domain_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(count)
    }

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

        match record {
            Some(mut r) => {
                // Decrypt secrets read from DB
                r.dkim_private_key = self.decrypt(&r.dkim_private_key)?;
                if let Some(ref key) = r.relay_api_key {
                    r.relay_api_key = Some(self.decrypt(key)?);
                }
                Ok(Some(r))
            }
            None => Ok(None),
        }
    }

    /// Look up address by ID (for ownership checks in handlers).
    pub async fn get_address_by_email_id(&self, address_id: Uuid) -> Result<Option<AddressOwnerRecord>> {
        let record = sqlx::query_as::<_, AddressOwnerRecord>(
            "SELECT id, owner_peer_id FROM mail_addresses WHERE id = $1"
        )
        .bind(address_id)
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
                let encrypted_key = self.encrypt(api_key)?;
                sqlx::query(
                    "UPDATE mail_addresses SET relay_provider = 'sendgrid', relay_api_key = $2,
                     relay_smtp_host = NULL, relay_smtp_port = NULL, relay_smtp_user = NULL, relay_mailgun_domain = NULL
                     WHERE email = $1"
                )
                .bind(email)
                .bind(&encrypted_key)
                .execute(&self.pool)
                .await?;
            }
            RelayConfig::Mailgun { api_key, domain } => {
                let encrypted_key = self.encrypt(api_key)?;
                sqlx::query(
                    "UPDATE mail_addresses SET relay_provider = 'mailgun', relay_api_key = $2,
                     relay_mailgun_domain = $3,
                     relay_smtp_host = NULL, relay_smtp_port = NULL, relay_smtp_user = NULL
                     WHERE email = $1"
                )
                .bind(email)
                .bind(&encrypted_key)
                .bind(domain)
                .execute(&self.pool)
                .await?;
            }
            RelayConfig::Smtp { host, port, username, password } => {
                let encrypted_password = self.encrypt(password)?;
                sqlx::query(
                    "UPDATE mail_addresses SET relay_provider = 'smtp', relay_api_key = $2,
                     relay_smtp_host = $3, relay_smtp_port = $4, relay_smtp_user = $5,
                     relay_mailgun_domain = NULL
                     WHERE email = $1"
                )
                .bind(email)
                .bind(&encrypted_password)
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
        raw_size: i64,
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

    /// Atomically claim a pending queue entry for reading (TOCTOU fix).
    /// Returns the entry only if it was in 'pending' status, and sets it to 'picked_up'.
    pub async fn claim_queue_entry(&self, queue_id: Uuid) -> Result<Option<QueueEntryRecord>> {
        let record = sqlx::query_as::<_, QueueEntryRecord>(
            "UPDATE mail_inbound_queue
             SET status = 'picked_up', picked_up_at = NOW()
             WHERE id = $1 AND status = 'pending'
             RETURNING id, address_id, message_id, storage_path, status"
        )
        .bind(queue_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
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

    /// Atomically claim expired pending entries for Path B processing (C3 TOCTOU fix).
    /// Uses UPDATE...RETURNING with FOR UPDATE SKIP LOCKED to prevent races with
    /// client pickup (claim_queue_entry) and other expiry worker instances.
    pub async fn claim_expired_batch(&self, max_retries: i32, limit: i64) -> Result<Vec<InboundQueueRecord>> {
        let records = sqlx::query_as::<_, InboundQueueRecord>(
            "UPDATE mail_inbound_queue
             SET status = 'expiry_processing'
             WHERE id IN (
                 SELECT q.id FROM mail_inbound_queue q
                 WHERE q.status = 'pending' AND q.expires_at < NOW() AND q.retry_count < $1
                 ORDER BY q.expires_at ASC
                 LIMIT $2
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, address_id, message_id, storage_path,
                       (SELECT a.owner_peer_id FROM mail_addresses a WHERE a.id = address_id) as owner_peer_id,
                       retry_count"
        )
        .bind(max_retries)
        .bind(limit)
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

    /// Increment retry count for a failed Path B attempt.
    pub async fn increment_retry_count(&self, queue_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE mail_inbound_queue SET retry_count = retry_count + 1 WHERE id = $1"
        )
        .bind(queue_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Mark entry as permanently failed after max retries exhausted.
    pub async fn mark_permanently_failed(&self, queue_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE mail_inbound_queue SET status = 'permanently_failed' WHERE id = $1"
        )
        .bind(queue_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ---- Outbound queue (H4: retry logic) ----

    pub async fn enqueue_outbound(
        &self,
        address_id: Uuid,
        sender: &str,
        recipients: &[String],
        cc: &[String],
        bcc: &[String],
        subject: &str,
        body: &str,
        content_type: &str,
    ) -> Result<Uuid> {
        // H8: Encrypt body at rest so pending outbound mail isn't readable if DB is compromised
        let encrypted_body = self.encrypt(body)?;

        let id = sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO mail_outbound_queue (address_id, sender, recipients, cc, bcc, subject, body, content_type)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id"
        )
        .bind(address_id)
        .bind(sender)
        .bind(recipients)
        .bind(cc)
        .bind(bcc)
        .bind(subject)
        .bind(&encrypted_body)
        .bind(content_type)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    /// Decrypt outbound body when reading from queue (H8 counterpart).
    pub fn decrypt_outbound_body(&self, encrypted_body: &str) -> Result<String> {
        self.decrypt(encrypted_body)
    }

    /// Claim the next batch of outbound messages ready for delivery.
    /// Atomically sets status to 'sending' so no other worker picks them up.
    pub async fn claim_outbound_batch(&self, limit: i64) -> Result<Vec<OutboundQueueRecord>> {
        let records = sqlx::query_as::<_, OutboundQueueRecord>(
            "UPDATE mail_outbound_queue
             SET status = 'sending', updated_at = NOW()
             WHERE id IN (
                 SELECT id FROM mail_outbound_queue
                 WHERE status = 'pending' AND next_retry_at <= NOW()
                 ORDER BY next_retry_at ASC
                 LIMIT $1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, address_id, sender, recipients, cc, bcc, subject, body, content_type, retry_count"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }

    /// Mark an outbound message as sent.
    pub async fn mark_outbound_sent(&self, queue_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE mail_outbound_queue SET status = 'sent', updated_at = NOW() WHERE id = $1"
        )
        .bind(queue_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Mark outbound message for retry with exponential backoff.
    /// Backoff: 30s, 2min, 8min, 32min, 2h (base 30s * 4^retry_count).
    pub async fn mark_outbound_retry(&self, queue_id: Uuid, error: &str) -> Result<()> {
        sqlx::query(
            "UPDATE mail_outbound_queue
             SET status = 'pending',
                 retry_count = retry_count + 1,
                 last_error = $2,
                 next_retry_at = NOW() + make_interval(secs => 30.0 * power(4, retry_count)),
                 updated_at = NOW()
             WHERE id = $1"
        )
        .bind(queue_id)
        .bind(error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Mark outbound message as permanently failed (5xx or max retries).
    pub async fn mark_outbound_failed(&self, queue_id: Uuid, error: &str) -> Result<()> {
        sqlx::query(
            "UPDATE mail_outbound_queue
             SET status = 'permanently_failed', last_error = $2, updated_at = NOW()
             WHERE id = $1"
        )
        .bind(queue_id)
        .bind(error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // ---- Tags ----

    pub async fn list_tags(&self, owner_peer_id: &str) -> Result<Vec<TagRecord>> {
        let records = sqlx::query_as::<_, TagRecord>(
            "SELECT id, name, color_argb, created_at
             FROM mail_tags
             WHERE owner_peer_id = $1
             ORDER BY created_at ASC",
        )
        .bind(owner_peer_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(records)
    }

    pub async fn create_tag(
        &self,
        owner_peer_id: &str,
        name: &str,
        color_argb: i64,
    ) -> Result<TagRecord> {
        let record = sqlx::query_as::<_, TagRecord>(
            "INSERT INTO mail_tags (owner_peer_id, name, color_argb)
             VALUES ($1, $2, $3)
             RETURNING id, name, color_argb, created_at",
        )
        .bind(owner_peer_id)
        .bind(name)
        .bind(color_argb)
        .fetch_one(&self.pool)
        .await?;
        Ok(record)
    }

    /// Returns true when a row was actually updated (respecting ownership).
    pub async fn update_tag(
        &self,
        owner_peer_id: &str,
        id: Uuid,
        name: Option<&str>,
        color_argb: Option<i64>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE mail_tags
             SET name       = COALESCE($3, name),
                 color_argb = COALESCE($4, color_argb)
             WHERE id = $1 AND owner_peer_id = $2",
        )
        .bind(id)
        .bind(owner_peer_id)
        .bind(name)
        .bind(color_argb)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_tag(&self, owner_peer_id: &str, id: Uuid) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM mail_tags WHERE id = $1 AND owner_peer_id = $2",
        )
        .bind(id)
        .bind(owner_peer_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    // ---- Queue cleanup (H9) ----

    /// Delete completed/failed queue entries older than retention_days.
    pub async fn cleanup_old_queue_entries(&self, retention_days: i64) -> Result<(u64, u64, u64)> {
        let inbound = sqlx::query(
            "DELETE FROM mail_inbound_queue
             WHERE status IN ('picked_up', 'fallback_encrypted', 'permanently_failed')
             AND created_at < NOW() - make_interval(days => $1)"
        )
        .bind(retention_days as f64)
        .execute(&self.pool)
        .await?
        .rows_affected();

        let outbound = sqlx::query(
            "DELETE FROM mail_outbound_queue
             WHERE status IN ('sent', 'permanently_failed')
             AND created_at < NOW() - make_interval(days => $1)"
        )
        .bind(retention_days as f64)
        .execute(&self.pool)
        .await?
        .rows_affected();

        let logs = sqlx::query(
            "DELETE FROM mail_delivery_log
             WHERE created_at < NOW() - make_interval(days => $1)"
        )
        .bind((retention_days * 3) as f64) // Keep logs 3x longer than queue entries
        .execute(&self.pool)
        .await?
        .rows_affected();

        Ok((inbound, outbound, logs))
    }

    /// Reset any 'sending' outbound entries back to 'pending' (stuck from crashed worker).
    /// Called on startup to recover from unclean shutdown (M8).
    pub async fn recover_stuck_outbound(&self) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE mail_outbound_queue SET status = 'pending', updated_at = NOW()
             WHERE status = 'sending'"
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Reset any 'expiry_processing' inbound entries back to 'pending' (stuck from crashed worker).
    pub async fn recover_stuck_inbound(&self) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE mail_inbound_queue SET status = 'pending'
             WHERE status = 'expiry_processing'"
        )
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Clear push token for an address (M6: stale FCM token cleanup).
    pub async fn clear_push_token(&self, address_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE mail_addresses SET push_token = NULL, push_platform = NULL WHERE id = $1"
        )
        .bind(address_id)
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
/// Users bring their own API key -- no IP warming needed for the gateway.
///
/// Debug impl redacts secrets to prevent leaking API keys in logs.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum RelayConfig {
    SendGrid { api_key: String },
    Mailgun { api_key: String, domain: String },
    Smtp { host: String, port: u16, username: String, password: String },
}

impl fmt::Debug for RelayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayConfig::SendGrid { .. } => {
                f.debug_struct("SendGrid").field("api_key", &"[REDACTED]").finish()
            }
            RelayConfig::Mailgun { domain, .. } => {
                f.debug_struct("Mailgun")
                    .field("api_key", &"[REDACTED]")
                    .field("domain", domain)
                    .finish()
            }
            RelayConfig::Smtp { host, port, username, .. } => {
                f.debug_struct("Smtp")
                    .field("host", host)
                    .field("port", port)
                    .field("username", username)
                    .field("password", &"[REDACTED]")
                    .finish()
            }
        }
    }
}

impl RelayConfig {
    pub fn provider_name(&self) -> &'static str {
        match self {
            RelayConfig::SendGrid { .. } => "sendgrid",
            RelayConfig::Mailgun { .. } => "mailgun",
            RelayConfig::Smtp { .. } => "smtp",
        }
    }
}

#[derive(sqlx::FromRow, Debug)]
pub struct PendingMailRecord {
    pub id: Uuid,
    pub message_id: String,
    pub sender: String,
    pub subject: Option<String>,
    pub raw_size: i64,
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
    pub retry_count: i32,
}

#[derive(sqlx::FromRow, Debug)]
pub struct AddressOwnerRecord {
    pub id: Uuid,
    pub owner_peer_id: String,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct TagRecord {
    pub id: Uuid,
    pub name: String,
    pub color_argb: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow, Debug)]
pub struct OutboundQueueRecord {
    pub id: Uuid,
    pub address_id: Uuid,
    pub sender: String,
    pub recipients: Vec<String>,
    #[sqlx(default)]
    pub cc: Vec<String>,
    #[sqlx(default)]
    pub bcc: Vec<String>,
    pub subject: String,
    pub body: String,
    pub content_type: String,
    pub retry_count: i32,
}
