-- merovingian-migration version=5 name=stream_ordering_and_membership_columns direction=upgrade
-- statement events_add_stream_ordering
ALTER TABLE events ADD COLUMN stream_ordering TEXT NOT NULL DEFAULT '0'
-- statement membership_add_membership_column
ALTER TABLE membership ADD COLUMN membership TEXT NOT NULL DEFAULT 'join'
-- statement membership_add_stream_ordering
ALTER TABLE membership ADD COLUMN stream_ordering TEXT NOT NULL DEFAULT '0'
-- statement invites_add_event_id
ALTER TABLE invites ADD COLUMN event_id TEXT NOT NULL DEFAULT ''
-- statement invites_add_stream_ordering
ALTER TABLE invites ADD COLUMN stream_ordering TEXT NOT NULL DEFAULT '0'