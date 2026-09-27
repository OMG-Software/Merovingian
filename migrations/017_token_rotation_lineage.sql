-- merovingian-migration version=17 name=token_rotation_lineage direction=upgrade
-- statement add_refresh_token_predecessor_column
ALTER TABLE refresh_tokens ADD COLUMN predecessor_hash TEXT NOT NULL DEFAULT ''
-- statement add_access_token_predecessor_column
ALTER TABLE access_tokens ADD COLUMN predecessor_refresh_hash TEXT NOT NULL DEFAULT ''
