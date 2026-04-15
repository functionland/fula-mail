-- Per-user outbound relay configuration (BYOK: SendGrid, Mailgun, or generic SMTP).
-- Users bring their own API key — no IP warming needed for the gateway.

ALTER TABLE mail_addresses ADD COLUMN IF NOT EXISTS relay_provider TEXT;          -- 'sendgrid', 'mailgun', 'smtp', or NULL (use global fallback)
ALTER TABLE mail_addresses ADD COLUMN IF NOT EXISTS relay_api_key TEXT;           -- API key (SendGrid/Mailgun) or SMTP password
ALTER TABLE mail_addresses ADD COLUMN IF NOT EXISTS relay_smtp_host TEXT;         -- SMTP host (generic SMTP only)
ALTER TABLE mail_addresses ADD COLUMN IF NOT EXISTS relay_smtp_port INTEGER;      -- SMTP port (generic SMTP only)
ALTER TABLE mail_addresses ADD COLUMN IF NOT EXISTS relay_smtp_user TEXT;         -- SMTP username (generic SMTP only)
ALTER TABLE mail_addresses ADD COLUMN IF NOT EXISTS relay_mailgun_domain TEXT;    -- Mailgun sending domain (may differ from user's email domain)
