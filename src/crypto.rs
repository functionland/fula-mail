//! Fula-client compatible encryption
//!
//! Replicates the same encryption used by FxFiles/FxMail:
//! - Ed25519 public key extracted from peer ID (on-chain)
//! - Ed25519 -> X25519 conversion (birational map)
//! - NaCl box (X25519 + XSalsa20-Poly1305) for per-message encryption
//!
//! The gateway ONLY uses public keys (from peer IDs). Private keys never leave the client.

use anyhow::{Context, Result};
use crypto_box::{
    aead::OsRng,
    PublicKey,
};

/// Extract Ed25519 public key (32 bytes) from a libp2p peer ID string.
///
/// Peer ID format (Ed25519, CIDv1 identity multihash):
///   base58btc([0x00, 0x24, 0x08, 0x01, 0x12, 0x20, ...32-byte-pubkey])
///
/// See identity-manager.js `peerIdFromEd25519PublicKey()` for the encoding side.
pub fn ed25519_pubkey_from_peer_id(peer_id: &str) -> Result<[u8; 32]> {
    let decoded = bs58::decode(peer_id)
        .into_vec()
        .context("Invalid base58 peer ID")?;

    // CIDv1 Ed25519: [0x00, 0x24, 0x08, 0x01, 0x12, 0x20, ...32 bytes]
    if decoded.len() >= 38
        && decoded[0] == 0x00
        && decoded[1] == 0x24
        && decoded[2] == 0x08
        && decoded[3] == 0x01
        && decoded[4] == 0x12
        && decoded[5] == 0x20
    {
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&decoded[6..38]);
        return Ok(pubkey);
    }

    // Legacy multihash: [0x12, 0x20, ...32 bytes]
    if decoded.len() == 34 && decoded[0] == 0x12 && decoded[1] == 0x20 {
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&decoded[2..34]);
        return Ok(pubkey);
    }

    anyhow::bail!(
        "Unsupported peer ID format (length={}, first bytes={:02x?})",
        decoded.len(),
        &decoded[..decoded.len().min(6)]
    )
}

/// Convert Ed25519 public key to X25519 public key for NaCl box encryption.
///
/// Uses the standard birational map (same as libsodium crypto_sign_ed25519_pk_to_curve25519).
pub fn ed25519_to_x25519_pubkey(ed25519_pk: &[u8; 32]) -> Result<PublicKey> {
    let ed_point = curve25519_dalek::edwards::CompressedEdwardsY(*ed25519_pk)
        .decompress()
        .context("Invalid Ed25519 public key point")?;

    let x25519_bytes = ed_point.to_montgomery().to_bytes();
    Ok(PublicKey::from(x25519_bytes))
}

/// Encrypt a message using NaCl sealed box (anonymous sender).
///
/// Sealed box = ephemeral X25519 keypair + NaCl box.
/// Only the holder of the corresponding private key can decrypt.
/// The gateway never learns who the recipient is beyond the public key.
///
/// This is the Path B encryption used when the client is offline.
/// Path A (client-side encryption) uses the same primitive but runs on the client device.
pub fn encrypt_for_peer(peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ed25519_pk = ed25519_pubkey_from_peer_id(peer_id)?;
    let x25519_pk = ed25519_to_x25519_pubkey(&ed25519_pk)?;

    let ciphertext = x25519_pk.seal(&mut OsRng, plaintext)
        .map_err(|e| anyhow::anyhow!("Sealed box encryption failed: {}", e))?;
    Ok(ciphertext)
}

/// Encrypt with an already-resolved X25519 public key (avoids repeated peer ID parsing).
pub fn encrypt_with_pubkey(pubkey: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    pubkey.seal(&mut OsRng, plaintext)
        .map_err(|e| anyhow::anyhow!("Sealed box encryption failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_pubkey_from_peer_id() {
        // Known test peer ID from identity-manager.js
        // 12D3KooWAazUofWiZPiTovPDTqk8pucGw5k9ruSfbwncaktWi7DN
        let peer_id = "12D3KooWAazUofWiZPiTovPDTqk8pucGw5k9ruSfbwncaktWi7DN";
        let result = ed25519_pubkey_from_peer_id(peer_id);
        assert!(result.is_ok(), "Should extract pubkey from valid peer ID");
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_invalid_peer_id() {
        let result = ed25519_pubkey_from_peer_id("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_roundtrip_structure() {
        // We can only test the encryption side (gateway has no private keys).
        // Verify that encryption produces valid ciphertext that is larger than plaintext
        // (sealed box adds 48 bytes: 32 ephemeral pk + 16 MAC).
        let peer_id = "12D3KooWAazUofWiZPiTovPDTqk8pucGw5k9ruSfbwncaktWi7DN";
        let plaintext = b"Subject: Test\r\n\r\nHello from Gmail";

        let result = encrypt_for_peer(peer_id, plaintext);
        assert!(result.is_ok());

        let ciphertext = result.unwrap();
        // Sealed box overhead: 32 (ephemeral pk) + 16 (MAC) = 48 bytes
        assert_eq!(ciphertext.len(), plaintext.len() + 48);
    }
}
