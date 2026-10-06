-- merovingian-migration version=19 name=to_device_queue_age_bound direction=upgrade
-- statement add_created_at_ms_column
ALTER TABLE to_device_messages ADD COLUMN created_at_ms TEXT NOT NULL DEFAULT '0'
-- statement create_recipient_age_index
CREATE INDEX idx_to_device_messages_recipient_age
    ON to_device_messages (target_user_id, target_device_id, created_at_ms)
