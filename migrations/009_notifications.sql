-- merovingian-migration version=9 name=notifications direction=upgrade
-- statement create_notifications
CREATE TABLE notifications (user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_id TEXT NOT NULL, stream_ordering TEXT NOT NULL DEFAULT '0', ts TEXT NOT NULL DEFAULT '0', actions TEXT NOT NULL DEFAULT '[]', profile_tag TEXT NOT NULL DEFAULT '', highlight TEXT NOT NULL DEFAULT 'false', PRIMARY KEY (user_id, event_id))
