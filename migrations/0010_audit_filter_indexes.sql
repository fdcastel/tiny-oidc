-- Every /admin/audit filter on an indexed column (spec §9.2, review M5):
-- actor_id and outcome were filtered by walking the whole hot table.
-- IF NOT EXISTS: on staging (7 M rows) the indexes were built by hand first
-- (2026-09-28): an index over that many rows took ~12 s and one attempt
-- ended in a D1 storage-timeout reset (7429), though it completed.
CREATE INDEX IF NOT EXISTS audit_hot_actor   ON audit_hot(actor_id, ts);
CREATE INDEX IF NOT EXISTS audit_hot_outcome ON audit_hot(outcome, ts);
