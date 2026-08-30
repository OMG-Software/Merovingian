-- merovingian-migration version=13 name=appservice_txn_cursor direction=upgrade
-- statement create_appservice_txn_cursor
CREATE TABLE appservice_txn_cursor (appservice_id TEXT NOT NULL PRIMARY KEY, next_txn_id TEXT NOT NULL DEFAULT '1', delivered_stream_ordering TEXT NOT NULL DEFAULT '0', pending_txn_id TEXT NOT NULL DEFAULT '0', pending_stream_ordering TEXT NOT NULL DEFAULT '0')
