-- Outbound mail queue for retry logic (H4).
-- Messages are queued on first attempt and retried with exponential backoff
-- on transient failures (4xx). Permanent failures (5xx) are marked immediately.

CREATE TABLE IF NOT EXISTS mail_outbound_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    address_id UUID NOT NULL REFERENCES mail_addresses(id),
    sender TEXT NOT NULL,
    recipients TEXT[] NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'text/plain',

    -- Delivery state
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sending', 'sent', 'permanently_failed')),
    retry_count INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_outbound_queue_pending
    ON mail_outbound_queue (next_retry_at)
    WHERE status = 'pending';
