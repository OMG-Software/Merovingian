-- merovingian-migration version=3 name=e2ee_key_storage direction=upgrade
-- statement create_device_keys
CREATE TABLE device_keys (user_id TEXT NOT NULL, device_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, device_id))
-- statement create_key_signatures
CREATE TABLE key_signatures (signer_user_id TEXT NOT NULL, target_user_id TEXT NOT NULL, target_device_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (signer_user_id, target_user_id, target_device_id))
-- statement create_key_backup_versions
CREATE TABLE key_backup_versions (user_id TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version))
-- statement create_key_backup_sessions
CREATE TABLE key_backup_sessions (user_id TEXT NOT NULL, version TEXT NOT NULL, room_id TEXT NOT NULL, session_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version, room_id, session_id))
