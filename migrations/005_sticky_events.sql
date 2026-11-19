-- merovingian-migration version=5 name=sticky_events direction=upgrade
-- statement create_sticky_events
CREATE TABLE "sticky_events" (event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, sender TEXT NOT NULL, received_at_ms TEXT NOT NULL, expires_at_ms TEXT NOT NULL)
-- statement create_delayed_event_sticky_durations
CREATE TABLE "delayed_event_sticky_durations" (delay_id TEXT PRIMARY KEY, sticky_duration_ms TEXT NOT NULL)
-- statement create_idx_sticky_events_room_id
CREATE INDEX idx_sticky_events_room_id ON sticky_events (room_id)
-- statement create_idx_sticky_events_sender
CREATE INDEX idx_sticky_events_sender ON sticky_events (sender)
