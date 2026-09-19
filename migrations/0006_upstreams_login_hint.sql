-- Whether the local login_hint is forwarded to the upstream (spec TIO-FED-010).
ALTER TABLE upstreams ADD COLUMN forward_login_hint INTEGER NOT NULL DEFAULT 0;
