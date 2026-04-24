-- Add Cc/Bcc columns to outbound queue.
-- Cc appears in the message header and envelope.
-- Bcc appears in the envelope only (stripped from the transmitted message).

ALTER TABLE mail_outbound_queue
    ADD COLUMN IF NOT EXISTS cc  TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE mail_outbound_queue
    ADD COLUMN IF NOT EXISTS bcc TEXT[] NOT NULL DEFAULT '{}';
