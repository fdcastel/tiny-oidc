-- Keyset paging of groups by (created_at, id) (spec §9.2, TIO-ADMIN-004).
CREATE INDEX groups_created ON groups(created_at, id);
