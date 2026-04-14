//! Outbound mail processing: DKIM signing and SMTP relay.
//!
//! Flow:
//! 1. FxMail submits plaintext message via HTTPS API (authenticated with JWT)
//! 2. Gateway looks up sender's domain DKIM key
//! 3. DKIM-signs the message
//! 4. Relays via SMTP (direct or via outbound relay for IP warming)
//! 5. Does NOT store plaintext (fire-and-forget)

// TODO: Implement outbound mail processing
// This module will contain:
// - DKIM signing logic using domain's private key from DB
// - SMTP client for direct delivery or relay
// - Bounce handling and DSN generation
