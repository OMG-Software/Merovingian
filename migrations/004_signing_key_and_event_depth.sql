-- merovingian-migration version=4 name=signing_key_and_event_depth direction=upgrade
-- statement alter_server_signing_keys_add_server_name
ALTER TABLE server_signing_keys ADD COLUMN server_name TEXT NOT NULL DEFAULT ''
-- statement recreate_server_signing_keys_pk
CREATE TABLE server_signing_keys_new (server_name TEXT NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, valid_until_ts TEXT NOT NULL, PRIMARY KEY (server_name, key_id))
-- statement copy_server_signing_keys
INSERT INTO server_signing_keys_new SELECT server_name, key_id, public_key, valid_until_ts FROM server_signing_keys
-- statement drop_old_server_signing_keys
DROP TABLE server_signing_keys
-- statement rename_server_signing_keys_new
ALTER TABLE server_signing_keys_new RENAME TO server_signing_keys
-- statement alter_events_add_depth
ALTER TABLE events ADD COLUMN depth TEXT NOT NULL DEFAULT '0'