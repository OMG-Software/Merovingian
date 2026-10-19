-- merovingian-migration version=24 name=receipts direction=upgrade
-- statement create_receipts
CREATE TABLE receipts (room_id TEXT NOT NULL, receipt_type TEXT NOT NULL, user_id TEXT NOT NULL, thread_id TEXT NOT NULL DEFAULT '', event_id TEXT NOT NULL, ts TEXT NOT NULL DEFAULT '0', stream_id TEXT NOT NULL DEFAULT '0', PRIMARY KEY (room_id, receipt_type, user_id, thread_id))
