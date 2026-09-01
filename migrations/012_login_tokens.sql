-- merovingian-migration version=12 name=login_tokens direction=upgrade
-- statement create_login_tokens
CREATE TABLE login_tokens (user_id TEXT NOT NULL, token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL DEFAULT '0', used TEXT NOT NULL DEFAULT 'false')
