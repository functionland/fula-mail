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
pub async fn run_expiry_worker(state: Arc<AppState>) -> anyhow::Result<()> {
    tracing::info!("Path A expiry worker started (TTL: {}s)", state.config.path_a_ttl_secs);

    loop {
        sleep(Duration::from_secs(30)).await;

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
    let expired = state.db.get_expired_pending().await?;
    let mut count = 0;

    for entry in expired {
        // Read raw message from temp storage
        let raw = match tokio::fs::read(&entry.storage_path).await {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Cannot read temp file {}: {}", entry.storage_path, e);
                continue;
            }
        };

        // Encrypt with recipient's public key (Path B)
        let encrypted = match crypto::encrypt_for_peer(&entry.owner_peer_id, &raw) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Encryption failed for peer {}: {}", entry.owner_peer_id, e);
                continue;
            }
        };

        // Store via pinning service
        let name = format!("mail:{}", entry.message_id);
        // Use system key for gateway-initiated pins
        let cid = match state.pinning.store_and_pin(&encrypted, &name, &state.config.pinning_system_key).await {
            Ok(cid) => cid,
            Err(e) => {
                tracing::error!("Pinning failed for {}: {}", entry.message_id, e);
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
