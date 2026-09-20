-- Per-client PKCE requirement (TIO-AUTHZ-008, Appendix B #37): on by default,
-- clearable only for confidential clients (the conformance suite sends none).
ALTER TABLE clients ADD COLUMN require_pkce INTEGER NOT NULL DEFAULT 1;
