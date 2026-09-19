-- Keyset paging of invitations by (created_at, id) (spec §9.2, TIO-ADMIN-004).
CREATE INDEX invitations_created ON invitations(created_at, id);
