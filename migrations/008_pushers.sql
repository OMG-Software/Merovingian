-- merovingian-migration version=8 name=pushers direction=upgrade
-- statement create_pushers
CREATE TABLE pushers (user_id TEXT NOT NULL, app_id TEXT NOT NULL, pushkey TEXT NOT NULL, kind TEXT NOT NULL, app_display_name TEXT NOT NULL DEFAULT '', device_display_name TEXT NOT NULL DEFAULT '', profile_tag TEXT NOT NULL DEFAULT '', lang TEXT NOT NULL DEFAULT '', data_url TEXT NOT NULL DEFAULT '', data_format TEXT NOT NULL DEFAULT '', PRIMARY KEY (user_id, app_id, pushkey))
