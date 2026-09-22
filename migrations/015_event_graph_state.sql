-- merovingian-migration version=15 name=event_graph_state direction=upgrade
-- statement events_add_status_column
ALTER TABLE events ADD COLUMN status TEXT NOT NULL DEFAULT 'accepted'
-- statement state_groups_add_parent_column
ALTER TABLE state_groups ADD COLUMN parent_state_group_id TEXT NOT NULL DEFAULT ''
-- statement state_groups_add_delta_depth_column
ALTER TABLE state_groups ADD COLUMN delta_depth TEXT NOT NULL DEFAULT '0'
-- statement create_state_group_state
CREATE TABLE state_group_state (state_group_id TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (state_group_id, event_type, state_key))
-- statement create_event_state_groups
CREATE TABLE event_state_groups (event_id TEXT PRIMARY KEY, state_group_id TEXT NOT NULL)
-- statement create_forward_extremities
CREATE TABLE forward_extremities (room_id TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (room_id, event_id))
-- statement create_event_edges_prev_event_id_index
CREATE INDEX event_edges_prev_event_id ON event_edges (prev_event_id)
-- statement seed_state_group_snapshots
INSERT INTO state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) SELECT 'seed:' || r.room_id, r.room_id, '', '0' FROM rooms r WHERE NOT EXISTS (SELECT 1 FROM state_groups g WHERE g.state_group_id = 'seed:' || r.room_id)
-- statement seed_state_group_state
INSERT INTO state_group_state (state_group_id, event_type, state_key, event_id) SELECT 'seed:' || c.room_id, c.event_type, c.state_key, c.event_id FROM current_state c WHERE NOT EXISTS (SELECT 1 FROM state_group_state s WHERE s.state_group_id = 'seed:' || c.room_id AND s.event_type = c.event_type AND s.state_key = c.state_key)
-- statement seed_forward_extremities
INSERT INTO forward_extremities (room_id, event_id) SELECT e.room_id, e.event_id FROM events e WHERE NOT EXISTS (SELECT 1 FROM event_edges g WHERE g.prev_event_id = e.event_id) AND NOT EXISTS (SELECT 1 FROM forward_extremities f WHERE f.room_id = e.room_id AND f.event_id = e.event_id)
-- statement seed_event_state_groups
INSERT INTO event_state_groups (event_id, state_group_id) SELECT f.event_id, 'seed:' || f.room_id FROM forward_extremities f WHERE NOT EXISTS (SELECT 1 FROM event_state_groups m WHERE m.event_id = f.event_id)
