-- merovingian-migration version=16 name=media_legacy_endpoint_visibility direction=upgrade
-- statement add_legacy_endpoint_visible_column
ALTER TABLE media ADD COLUMN legacy_endpoint_visible TEXT NOT NULL DEFAULT 'true'
