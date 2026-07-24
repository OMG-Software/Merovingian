-- merovingian-migration version=4 name=state_transitions direction=upgrade
-- statement create_state_transitions
CREATE TABLE state_transitions (room_id TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT NOT NULL, previous_event_id TEXT NOT NULL DEFAULT '', PRIMARY KEY (room_id, event_type, state_key, event_id))

