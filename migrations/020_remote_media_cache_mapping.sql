-- merovingian-migration version=20 name=remote_media_cache_mapping direction=upgrade
-- statement add_remote_media_local_media_id_column
ALTER TABLE remote_media ADD COLUMN local_media_id TEXT NOT NULL DEFAULT ''
-- statement add_remote_media_fetched_at_ms_column
ALTER TABLE remote_media ADD COLUMN fetched_at_ms TEXT NOT NULL DEFAULT '0'
