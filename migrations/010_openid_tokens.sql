-- merovingian-migration version=10 name=openid_tokens direction=upgrade
-- statement create_openid_tokens
CREATE TABLE openid_tokens (user_id TEXT NOT NULL, token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL DEFAULT '0')
