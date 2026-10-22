-- merovingian-migration version=26 name=media_upload_names_and_pending_uploads direction=upgrade
-- statement add_media_upload_name_column
ALTER TABLE media ADD COLUMN upload_name TEXT NOT NULL DEFAULT ''
-- statement create_media_pending_uploads
CREATE TABLE media_pending_uploads (media_id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, created_at_ms TEXT NOT NULL, expires_at_ms TEXT NOT NULL)
-- statement create_media_pending_uploads_owner_index
CREATE INDEX idx_media_pending_uploads_owner ON media_pending_uploads (owner_user_id)
