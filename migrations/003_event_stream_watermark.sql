-- merovingian-migration version=3 name=event_stream_watermark direction=upgrade
-- statement create_event_stream_watermark
CREATE TABLE event_stream_watermark (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), watermark TEXT NOT NULL DEFAULT '0')
