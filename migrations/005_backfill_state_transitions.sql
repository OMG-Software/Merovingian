-- merovingian-migration version=5 name=backfill_state_transitions direction=upgrade
-- statement backfill_state_transitions
INSERT INTO state_transitions (room_id, event_type, state_key, event_id, previous_event_id)
SELECT c.room_id, c.event_type, c.state_key, c.event_id, '' FROM current_state c
LEFT JOIN state_transitions t
    ON t.room_id = c.room_id AND t.event_type = c.event_type AND t.state_key = c.state_key AND t.event_id = c.event_id
WHERE t.room_id IS NULL
