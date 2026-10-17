-- merovingian-migration version=22 name=appservice_outbox direction=upgrade
-- statement create_appservice_outbox
CREATE TABLE appservice_outbox (appservice_id TEXT NOT NULL, stream_ordering TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (appservice_id, stream_ordering))
