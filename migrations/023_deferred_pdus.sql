-- merovingian-migration version=23 name=deferred_pdus direction=upgrade
-- statement create_deferred_pdus
CREATE TABLE deferred_pdus (event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, origin TEXT NOT NULL, pdu_json TEXT NOT NULL, received_at_ms TEXT NOT NULL DEFAULT '0', attempts TEXT NOT NULL DEFAULT '0')
-- statement create_deferred_pdus_room_index
CREATE INDEX idx_deferred_pdus_room_id ON deferred_pdus (room_id)
