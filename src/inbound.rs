//! Inbound mail processing: Path A pickup + Path B fallback expiry worker.

use std::sync::Arc;
use tokio::time::{sleep, Duration};

use crate::{crypto, server::AppState};

/// Background worker that checks for expired Path A queue entries
/// and falls back to Path B (gateway-side encryption + pinning).
///
/// Runs every 30 seconds. For each expired entry:
/// 1. Read the raw message from temp storage
/// 2. Look up recipient's peer ID -> extract Ed25519 public key
/// 3. Encrypt with fula-client encryption (NaCl sealed box)
/// 4. Store encrypted blob via pinning service
/// 5. Mark queue entry as fallback_encrypted with the CID
/// 6. Delete temp file
///
/// Failed entries are retried up to max_retries times, then marked permanently_failed.
pub async fn run_expiry_worker(state: Arc<AppState>) -> anyhow::Result<()> {
    let poll_secs = state.config.expiry_poll_secs;
    tracing::info!("Path A expiry worker started (TTL: {}s, max_retries: {}, poll_interval: {}s)",
        state.config.path_a_ttl_secs, state.config.max_retries, poll_secs);

    loop {
        sleep(Duration::from_secs(poll_secs)).await;

        match process_expired(&state).await {
            Ok(count) if count > 0 => {
                tracing::info!("Processed {} expired Path A entries (fell back to Path B)", count);
            }
            Err(e) => {
                tracing::error!("Expiry worker error: {}", e);
            }
            _ => {}
        }
    }
}

async fn process_expired(state: &AppState) -> anyhow::Result<usize> {
    // C3: Atomic claim — prevents TOCTOU race with client pickup (claim_queue_entry).
    // Entries are set to 'expiry_processing' atomically, so claim_queue_entry
    // (which requires status='pending') will correctly fail for already-claimed entries.
    let expired = state.db.claim_expired_batch(state.config.max_retries, 20).await?;
    let mut count = 0;

    for entry in expired {
        // Read raw message from temp storage
        let raw = match tokio::fs::read(&entry.storage_path).await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Cannot read temp file {}: {}", entry.storage_path, e);
                // File missing -- mark permanently failed, nothing to retry
                state.db.mark_permanently_failed(entry.id).await?;
                state.db.log_delivery(
                    "inbound", Some(entry.address_id), Some(&entry.message_id),
                    "", "", "failed", None,
                    Some(&format!("Temp file unreadable: {}", e)), None,
                ).await?;
                continue;
            }
        };

        // Encrypt with recipient's public key (Path B)
        let encrypted = match crypto::encrypt_for_peer(&entry.owner_peer_id, &raw) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Encryption failed for peer {} (retry {}/{}): {}",
                    entry.owner_peer_id, entry.retry_count + 1, state.config.max_retries, e);
                state.db.increment_retry_count(entry.id).await?;
                if entry.retry_count + 1 >= state.config.max_retries {
                    state.db.mark_permanently_failed(entry.id).await?;
                    state.db.log_delivery(
                        "inbound", Some(entry.address_id), Some(&entry.message_id),
                        "", "", "failed", None,
                        Some(&format!("Encryption permanently failed: {}", e)), None,
                    ).await?;
                    let _ = tokio::fs::remove_file(&entry.storage_path).await;
                }
                continue;
            }
        };

        // Store via pinning service
        let name = format!("mail:{}", entry.message_id);
        // Use system key for gateway-initiated pins
        let cid = match state.pinning.store_and_pin(&encrypted, &name, &state.config.pinning_system_key).await {
            Ok(cid) => cid,
            Err(e) => {
                tracing::error!("Pinning failed for {} (retry {}/{}): {}",
                    entry.message_id, entry.retry_count + 1, state.config.max_retries, e);
                state.db.increment_retry_count(entry.id).await?;
                if entry.retry_count + 1 >= state.config.max_retries {
                    state.db.mark_permanently_failed(entry.id).await?;
                    state.db.log_delivery(
                        "inbound", Some(entry.address_id), Some(&entry.message_id),
                        "", "", "failed", None,
                        Some(&format!("Pinning permanently failed: {}", e)), None,
                    ).await?;
                    let _ = tokio::fs::remove_file(&entry.storage_path).await;
                }
                continue;
            }
        };

        // Update queue entry
        state.db.mark_fallback_encrypted(entry.id, &cid).await?;

        // Clean up temp file
        let _ = tokio::fs::remove_file(&entry.storage_path).await;

        // Log delivery
        state.db.log_delivery(
            "inbound",
            Some(entry.address_id),
            Some(&entry.message_id),
            "", // sender not stored in queue record (simplification)
            "",
            "delivered",
            None,
            Some("Path B fallback: gateway-encrypted"),
            Some(&cid),
        ).await?;

        count += 1;
    }

    Ok(count)
}
