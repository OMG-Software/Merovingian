-- merovingian-migration version=1 name=initial_schema direction=upgrade
-- statement create_schema_migrations
CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, name TEXT NOT NULL, direction TEXT NOT NULL)
-- statement create_users
CREATE TABLE users (user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, locked TEXT NOT NULL, suspended TEXT NOT NULL, admin TEXT NOT NULL)
-- statement create_devices
CREATE TABLE devices (user_id TEXT NOT NULL, device_id TEXT NOT NULL, display_name TEXT NOT NULL, PRIMARY KEY (user_id, device_id))
-- statement create_access_tokens
CREATE TABLE access_tokens (user_id TEXT NOT NULL, device_id TEXT NOT NULL, token_hash TEXT PRIMARY KEY, revoked TEXT NOT NULL)
-- statement create_refresh_tokens
CREATE TABLE refresh_tokens (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL, revoked TEXT NOT NULL)
-- statement create_server_signing_keys
CREATE TABLE server_signing_keys (server_name TEXT NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, valid_until_ts TEXT NOT NULL, secret_key TEXT, PRIMARY KEY (server_name, key_id))
-- statement create_rooms
CREATE TABLE rooms (room_id TEXT PRIMARY KEY, creator_user_id TEXT NOT NULL)
-- statement create_room_aliases
CREATE TABLE room_aliases (room_alias TEXT PRIMARY KEY, room_id TEXT NOT NULL)
-- statement create_room_versions
CREATE TABLE room_versions (room_id TEXT PRIMARY KEY, version TEXT NOT NULL)
-- statement create_events
CREATE TABLE events (event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, json TEXT NOT NULL, depth TEXT NOT NULL, stream_ordering TEXT NOT NULL DEFAULT '0')
-- statement create_event_json
CREATE TABLE event_json (event_id TEXT PRIMARY KEY, json TEXT NOT NULL)
-- statement create_event_edges
CREATE TABLE event_edges (event_id TEXT NOT NULL, prev_event_id TEXT NOT NULL, PRIMARY KEY (event_id, prev_event_id))
-- statement create_event_auth
CREATE TABLE event_auth (event_id TEXT NOT NULL, auth_event_id TEXT NOT NULL, PRIMARY KEY (event_id, auth_event_id))
-- statement create_event_signatures
CREATE TABLE event_signatures (event_id TEXT NOT NULL, server_name TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL, PRIMARY KEY (event_id, server_name, key_id))
-- statement create_current_state
CREATE TABLE current_state (room_id TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (room_id, event_type, state_key))
-- statement create_state_groups
CREATE TABLE state_groups (state_group_id TEXT PRIMARY KEY, room_id TEXT NOT NULL)
-- statement create_state_group_edges
CREATE TABLE state_group_edges (state_group_id TEXT NOT NULL, prev_state_group_id TEXT NOT NULL, PRIMARY KEY (state_group_id, prev_state_group_id))
-- statement create_membership
CREATE TABLE membership (room_id TEXT NOT NULL, user_id TEXT NOT NULL, membership TEXT NOT NULL DEFAULT 'join', stream_ordering TEXT NOT NULL DEFAULT '0', PRIMARY KEY (room_id, user_id))
-- statement create_invites
CREATE TABLE invites (room_id TEXT NOT NULL, user_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, event_id TEXT NOT NULL DEFAULT '', signed_event_json TEXT NOT NULL DEFAULT '', invite_state_json TEXT NOT NULL DEFAULT '[]', stream_ordering TEXT NOT NULL DEFAULT '0', PRIMARY KEY (room_id, user_id))
-- statement create_account_data
CREATE TABLE account_data (user_id TEXT NOT NULL, event_type TEXT NOT NULL, json TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '0', PRIMARY KEY (user_id, event_type))
-- statement create_room_account_data
CREATE TABLE room_account_data (user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_type TEXT NOT NULL, stream_id TEXT NOT NULL DEFAULT '0', json TEXT NOT NULL, PRIMARY KEY (user_id, room_id, event_type))
-- statement create_push_rules
CREATE TABLE push_rules (user_id TEXT NOT NULL, rule_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, rule_id))
-- statement create_filters
CREATE TABLE filters (user_id TEXT NOT NULL, filter_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, filter_id))
-- statement create_device_keys
CREATE TABLE device_keys (user_id TEXT NOT NULL, device_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, device_id))
-- statement create_one_time_keys
CREATE TABLE one_time_keys (user_id TEXT NOT NULL, device_id TEXT NOT NULL, key_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, device_id, key_id))
-- statement create_fallback_keys
CREATE TABLE fallback_keys (user_id TEXT NOT NULL, device_id TEXT NOT NULL, key_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, device_id, key_id))
-- statement create_cross_signing_keys
CREATE TABLE cross_signing_keys (user_id TEXT NOT NULL, key_type TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, key_type))
-- statement create_key_signatures
CREATE TABLE key_signatures (signer_user_id TEXT NOT NULL, target_user_id TEXT NOT NULL, target_device_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (signer_user_id, target_user_id, target_device_id))
-- statement create_key_backups
CREATE TABLE key_backups (user_id TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version))
-- statement create_key_backup_versions
CREATE TABLE key_backup_versions (user_id TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version))
-- statement create_key_backup_sessions
CREATE TABLE key_backup_sessions (user_id TEXT NOT NULL, version TEXT NOT NULL, room_id TEXT NOT NULL, session_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version, room_id, session_id))
-- statement create_media
CREATE TABLE media (media_id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, content_type TEXT NOT NULL, size_bytes TEXT NOT NULL, hash_algorithm TEXT NOT NULL, digest TEXT NOT NULL, quarantined TEXT NOT NULL, removed TEXT NOT NULL)
-- statement create_media_blobs
CREATE TABLE media_blobs (storage_id TEXT PRIMARY KEY, hash_algorithm TEXT NOT NULL, digest TEXT NOT NULL, size_bytes TEXT NOT NULL, bytes TEXT NOT NULL, ref_count TEXT NOT NULL)
-- statement create_remote_media
CREATE TABLE remote_media (server_name TEXT NOT NULL, media_id TEXT NOT NULL, content_type TEXT NOT NULL, size_bytes TEXT NOT NULL, quarantined TEXT NOT NULL, PRIMARY KEY (server_name, media_id))
-- statement create_federation_destinations
CREATE TABLE federation_destinations (server_name TEXT PRIMARY KEY, state TEXT NOT NULL, retry_after_ts TEXT NOT NULL, last_success_ts TEXT NOT NULL, consecutive_failures TEXT NOT NULL)
-- statement create_federation_transactions
CREATE TABLE federation_transactions (transaction_id TEXT PRIMARY KEY, server_name TEXT NOT NULL, json TEXT NOT NULL, method TEXT NOT NULL, target TEXT NOT NULL, origin TEXT NOT NULL, origin_server_ts TEXT NOT NULL, body TEXT NOT NULL, retry_count TEXT NOT NULL, next_retry_ts TEXT NOT NULL)
-- statement create_rate_limits
CREATE TABLE rate_limits (scope TEXT NOT NULL, key TEXT NOT NULL, count TEXT NOT NULL, reset_ts TEXT NOT NULL, PRIMARY KEY (scope, key))
-- statement create_audit_log
CREATE TABLE audit_log (category TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL)
-- statement create_policy_rules
CREATE TABLE policy_rules (rule_id TEXT PRIMARY KEY, scope TEXT NOT NULL, entity TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL)
-- statement create_admin_actions
CREATE TABLE admin_actions (admin_user_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL)
-- statement create_to_device_messages
CREATE TABLE to_device_messages (stream_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, target_user_id TEXT NOT NULL, target_device_id TEXT NOT NULL DEFAULT '', message_type TEXT NOT NULL, content TEXT NOT NULL, PRIMARY KEY (stream_id, target_user_id, target_device_id))
-- statement create_device_list_changes
CREATE TABLE device_list_changes (stream_id TEXT NOT NULL, observer_user_id TEXT NOT NULL, subject_user_id TEXT NOT NULL, change_type TEXT NOT NULL DEFAULT 'changed', PRIMARY KEY (stream_id, observer_user_id, subject_user_id))
-- statement create_presence_state
CREATE TABLE presence_state (user_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL DEFAULT '0', presence TEXT NOT NULL DEFAULT 'offline', status_msg TEXT NOT NULL DEFAULT '', last_active_ago TEXT NOT NULL DEFAULT '0', currently_active TEXT NOT NULL DEFAULT 'false')
-- statement create_profiles
CREATE TABLE profiles (user_id TEXT PRIMARY KEY, displayname TEXT NOT NULL DEFAULT '', avatar_url TEXT NOT NULL DEFAULT '')
-- statement create_client_txn_ids
CREATE TABLE client_txn_ids (user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_type TEXT NOT NULL, txn_id TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (user_id, room_id, event_type, txn_id))
