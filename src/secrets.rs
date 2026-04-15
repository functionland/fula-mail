//! Envelope encryption for secrets at rest (DKIM private keys, relay API keys).
//!
//! Uses AES-256-GCM with a master key from the ENCRYPTION_MASTER_KEY env var.
//! Each encrypted value is stored as: hex(nonce || ciphertext || tag).
//!
//! When no master key is configured, values are stored/read as plaintext
//! (backwards-compatible with existing deployments).

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore, Key, Nonce,
};
use anyhow::{Context, Result};

/// Encrypt a secret for storage in the database.
/// Returns hex-encoded ciphertext (nonce || encrypted || tag).
///
/// If no master key is configured, returns the plaintext unchanged.
pub fn encrypt_secret(plaintext: &str, master_key: Option<&str>) -> Result<String> {
    let key_hex = match master_key {
        Some(k) if !k.is_empty() => k,
        _ => return Ok(plaintext.to_string()),
    };

    let key_bytes = hex::decode(key_hex)
        .context("ENCRYPTION_MASTER_KEY must be valid hex")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("ENCRYPTION_MASTER_KEY must be exactly 32 bytes (64 hex chars)");
    }

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Format: hex(nonce || ciphertext)
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(hex::encode(combined))
}

/// Decrypt a secret read from the database.
/// Expects hex-encoded ciphertext (nonce || encrypted || tag).
///
/// If no master key is configured, returns the value unchanged (plaintext mode).
pub fn decrypt_secret(stored: &str, master_key: Option<&str>) -> Result<String> {
    let key_hex = match master_key {
        Some(k) if !k.is_empty() => k,
        _ => return Ok(stored.to_string()),
    };

    let key_bytes = hex::decode(key_hex)
        .context("ENCRYPTION_MASTER_KEY must be valid hex")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("ENCRYPTION_MASTER_KEY must be exactly 32 bytes (64 hex chars)");
    }

    let combined = hex::decode(stored)
        .context("Stored secret is not valid hex (expected encrypted format)")?;

    if combined.len() < 12 {
        anyhow::bail!("Encrypted secret too short");
    }

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&combined[..12]);
    let ciphertext = &combined[12..];

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed (wrong master key or corrupted data)"))?;

    String::from_utf8(plaintext)
        .context("Decrypted secret is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_master_key_passthrough() {
        let secret = "SG.my_api_key_here";
        assert_eq!(encrypt_secret(secret, None).unwrap(), secret);
        assert_eq!(decrypt_secret(secret, None).unwrap(), secret);
        assert_eq!(encrypt_secret(secret, Some("")).unwrap(), secret);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate a 32-byte key as hex
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let secret = "SG.my_sendgrid_api_key_12345";

        let encrypted = encrypt_secret(secret, Some(key_hex)).unwrap();
        assert_ne!(encrypted, secret); // Must be different from plaintext
        assert!(encrypted.len() > secret.len()); // Must be longer (nonce + tag)

        let decrypted = decrypt_secret(&encrypted, Some(key_hex)).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key2 = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
        let secret = "smtp_password_123";

        let encrypted = encrypt_secret(secret, Some(key1)).unwrap();
        assert!(decrypt_secret(&encrypted, Some(key2)).is_err());
    }
}
