-- merovingian-migration version=3 name=delayed_events direction=upgrade
-- statement create_delayed_events
CREATE TABLE "delayed_events" (delay_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL, room_id TEXT NOT NULL, event_type TEXT NOT NULL, is_state TEXT NOT NULL, state_key TEXT NOT NULL, content_json TEXT NOT NULL, txn_id TEXT NOT NULL, via_appservice TEXT NOT NULL, delay_ms TEXT NOT NULL, delayed_since_ms TEXT NOT NULL, status TEXT NOT NULL, finalised_at_ms TEXT NOT NULL, event_id TEXT NOT NULL, error_json TEXT NOT NULL)
-- statement create_idx_delayed_events_user_id
CREATE INDEX idx_delayed_events_user_id ON delayed_events (user_id)
