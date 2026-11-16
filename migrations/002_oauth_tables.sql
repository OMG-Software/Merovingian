-- merovingian-migration version=2 name=oauth_tables direction=upgrade
-- statement create_oauth_clients
CREATE TABLE "oauth_clients" (client_id TEXT PRIMARY KEY, metadata_json TEXT NOT NULL, created_at_ms TEXT NOT NULL, last_used_at_ms TEXT NOT NULL)
-- statement create_oauth_sessions
CREATE TABLE "oauth_sessions" (user_id TEXT NOT NULL, device_id TEXT NOT NULL, client_id TEXT NOT NULL, scope TEXT NOT NULL, created_at_ms TEXT NOT NULL, PRIMARY KEY (user_id, device_id))
-- statement create_idx_oauth_sessions_client_id
CREATE INDEX idx_oauth_sessions_client_id ON oauth_sessions (client_id)
