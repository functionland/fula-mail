-- Production hardening: retry tracking, status constraints, raw_size type fix.

-- Retry counter for Path B fallback (tracks failed encryption/pinning attempts)
ALTER TABLE mail_inbound_queue ADD COLUMN IF NOT EXISTS retry_count INTEGER NOT NULL DEFAULT 0;

-- Change raw_size to BIGINT to avoid overflow on large messages
-- (safe: existing i32 values fit in BIGINT)
ALTER TABLE mail_inbound_queue ALTER COLUMN raw_size TYPE BIGINT;

-- CHECK constraints on status enum columns
DO $$ BEGIN
    ALTER TABLE mail_domains ADD CONSTRAINT chk_domain_status
        CHECK (status IN ('pending_verification', 'active', 'suspended'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Drop old constraint if it exists (missing expiry_processing status)
ALTER TABLE mail_inbound_queue DROP CONSTRAINT IF EXISTS chk_queue_status;
DO $$ BEGIN
    ALTER TABLE mail_inbound_queue ADD CONSTRAINT chk_queue_status
        CHECK (status IN ('pending', 'picked_up', 'expired', 'fallback_encrypted', 'permanently_failed', 'expiry_processing'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE mail_delivery_log ADD CONSTRAINT chk_delivery_direction
        CHECK (direction IN ('inbound', 'outbound'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    ALTER TABLE mail_delivery_log ADD CONSTRAINT chk_delivery_status
        CHECK (status IN ('queued', 'delivered', 'sent', 'bounced', 'deferred', 'rejected', 'spam_filtered', 'failed'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
