-- User-defined tags for FxMail.
-- Tag DEFINITIONS (id/name/color) live on the server so they sync across devices.
-- Tag ASSIGNMENTS (which messages have which tags) live encrypted client-side
-- via fula_client, so the server cannot correlate tags to message content.

CREATE TABLE IF NOT EXISTS mail_tags (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_peer_id  TEXT NOT NULL,
    name           TEXT NOT NULL,
    color_argb     BIGINT NOT NULL DEFAULT 4288585374,  -- 0xFF9E9E9E (grey)
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Each user cannot have two tags with the same name.
CREATE UNIQUE INDEX IF NOT EXISTS mail_tags_owner_name_uq
    ON mail_tags (owner_peer_id, name);

CREATE INDEX IF NOT EXISTS mail_tags_owner_idx
    ON mail_tags (owner_peer_id);
