-- Personal data retention (TIO-PRIV-002, TIO-DATA-010, ADR 0020).
-- Invitations are deleted 30 days after use as well as after expiry (§4.7):
-- the cron's condition needs used_at indexed.
CREATE INDEX invitations_used ON invitations(used_at);

-- Admin diffs recorded before ADR 0020 carried the email and display name
-- they changed; they keep only the fact of the change, as new ones do. Only
-- user events carry these fields, and the (type, ts) index bounds the scan.
UPDATE audit_hot SET data = json_set(data, '$.diff.email', json('{"changed":true}'))
  WHERE type >= 'user.' AND type < 'user/' AND json_extract(data, '$.diff.email') IS NOT NULL;
UPDATE audit_hot SET data = json_set(data, '$.diff.email_norm', json('{"changed":true}'))
  WHERE type >= 'user.' AND type < 'user/' AND json_extract(data, '$.diff.email_norm') IS NOT NULL;
UPDATE audit_hot SET data = json_set(data, '$.diff.display_name', json('{"changed":true}'))
  WHERE type >= 'user.' AND type < 'user/' AND json_extract(data, '$.diff.display_name') IS NOT NULL;
