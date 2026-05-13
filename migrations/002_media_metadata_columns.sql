-- merovingian-migration version=2 name=media_metadata_columns direction=upgrade
-- statement media_add_hash_algorithm
ALTER TABLE media ADD COLUMN hash_algorithm TEXT NOT NULL DEFAULT 'blake2b'
-- statement media_add_digest
ALTER TABLE media ADD COLUMN digest TEXT NOT NULL DEFAULT 'unknown'
-- statement media_add_removed
ALTER TABLE media ADD COLUMN removed TEXT NOT NULL DEFAULT 'false'
