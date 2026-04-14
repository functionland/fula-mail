-- Fula Mail: Email-specific tables
-- Added to the shared pinning_service database.
-- NO duplication of existing tables (users, sessions, pins are in pinning-service schema).

-- ============================================
-- Custom Domains
-- ============================================
CREATE TABLE IF NOT EXISTS mail_domains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain TEXT NOT NULL UNIQUE,
    owner_peer_id TEXT NOT NULL,          -- references user's on-chain peer ID (NOT duplicated from users table)
    status TEXT NOT NULL DEFAULT 'pending_verification',  -- pending_verification, active, suspended
    mx_verified BOOLEAN NOT NULL DEFAULT FALSE,
    spf_verified BOOLEAN NOT NULL DEFAULT FALSE,
    dkim_verified BOOLEAN NOT NULL DEFAULT FALSE,
    dmarc_verified BOOLEAN NOT NULL DEFAULT FALSE,
    dkim_selector TEXT NOT NULL DEFAULT 'fula',
    dkim_private_key TEXT NOT NULL,       -- PEM-encoded RSA private key for DKIM signing
    dkim_public_key TEXT NOT NULL,        -- PEM-encoded RSA public key (for DNS TXT record)
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_domains_owner ON mail_domains(owner_peer_id);
CREATE INDEX IF NOT EXISTS idx_mail_domains_status ON mail_domains(status);

-- ============================================
-- Email Addresses -> Peer ID Mapping
-- ============================================
CREATE TABLE IF NOT EXISTS mail_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,           -- user@mydomain.com
    domain_id UUID NOT NULL REFERENCES mail_domains(id) ON DELETE CASCADE,
    owner_peer_id TEXT NOT NULL,          -- same peer ID as in pinning-service users table
    push_token TEXT,                      -- FCM/APNs token for Path A notifications
    push_platform TEXT,                   -- 'fcm' or 'apns'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_addresses_domain ON mail_addresses(domain_id);
CREATE INDEX IF NOT EXISTS idx_mail_addresses_peer ON mail_addresses(owner_peer_id);

-- ============================================
-- Inbound Queue (Path A: pending client pickup)
-- ============================================
-- Temporary storage for inbound mail waiting for client to fetch + encrypt.
-- Purged after client picks up, or after TTL expires (falls back to Path B).
CREATE TABLE IF NOT EXISTS mail_inbound_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address_id UUID NOT NULL REFERENCES mail_addresses(id) ON DELETE CASCADE,
    message_id TEXT NOT NULL,             -- RFC 5322 Message-ID
    sender TEXT NOT NULL,                 -- envelope From
    subject TEXT,                         -- for push notification preview
    raw_size INTEGER NOT NULL,            -- size in bytes
    storage_path TEXT NOT NULL,           -- temporary file path on gateway
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, picked_up, expired, fallback_encrypted
    fallback_cid TEXT,                    -- CID if fell back to Path B (gateway-encrypted)
    expires_at TIMESTAMPTZ NOT NULL,      -- TTL for Path A pickup (e.g., 5 minutes)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    picked_up_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_mail_inbound_queue_address ON mail_inbound_queue(address_id, status);
CREATE INDEX IF NOT EXISTS idx_mail_inbound_queue_expires ON mail_inbound_queue(expires_at) WHERE status = 'pending';

-- ============================================
-- Bounce/Delivery Tracking
-- ============================================
CREATE TABLE IF NOT EXISTS mail_delivery_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    direction TEXT NOT NULL,              -- 'inbound' or 'outbound'
    address_id UUID REFERENCES mail_addresses(id),
    message_id TEXT,
    sender TEXT NOT NULL,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL,                 -- 'delivered', 'bounced', 'deferred', 'rejected', 'spam_filtered'
    smtp_code INTEGER,
    smtp_response TEXT,
    encrypted_cid TEXT,                   -- CID of encrypted blob (if stored)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mail_delivery_log_address ON mail_delivery_log(address_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mail_delivery_log_status ON mail_delivery_log(status, created_at DESC);

-- ============================================
-- Updated-at trigger (reusable)
-- ============================================
CREATE OR REPLACE FUNCTION mail_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$ BEGIN
    CREATE TRIGGER mail_domains_updated_at BEFORE UPDATE ON mail_domains
        FOR EACH ROW EXECUTE FUNCTION mail_update_timestamp();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TRIGGER mail_addresses_updated_at BEFORE UPDATE ON mail_addresses
        FOR EACH ROW EXECUTE FUNCTION mail_update_timestamp();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
