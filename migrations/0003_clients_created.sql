-- Keyset paging of clients by (created_at, client_id) (spec §9.2, TIO-ADMIN-004).
CREATE INDEX clients_created ON clients(created_at, client_id);
