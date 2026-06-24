-- merovingian-migration version=2 name=sync_stream_watermark direction=upgrade
-- statement create_sync_stream_watermark
CREATE TABLE sync_stream_watermark (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), watermark TEXT NOT NULL DEFAULT '0')
