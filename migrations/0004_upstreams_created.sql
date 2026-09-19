-- Keyset paging of upstreams by (created_at, alias) (spec §9.2, TIO-ADMIN-004).
CREATE INDEX upstreams_created ON upstreams(created_at, alias);
