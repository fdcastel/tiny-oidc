-- The remaining fields of the §11.1 event on the hot table, so the per-user
-- views (§8, §9.4) answer without unpacking JSON.
ALTER TABLE audit_hot ADD COLUMN sid TEXT;
ALTER TABLE audit_hot ADD COLUMN interaction_id TEXT;
ALTER TABLE audit_hot ADD COLUMN country TEXT;
ALTER TABLE audit_hot ADD COLUMN ua_family TEXT;
ALTER TABLE audit_hot ADD COLUMN request_id TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_hot ADD COLUMN reason TEXT;
