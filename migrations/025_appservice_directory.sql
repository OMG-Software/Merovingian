-- merovingian-migration version=25 name=appservice_directory direction=upgrade
-- statement create_appservice_directory
CREATE TABLE appservice_directory (appservice_id TEXT NOT NULL, network_id TEXT NOT NULL, room_id TEXT NOT NULL, PRIMARY KEY (appservice_id, network_id, room_id))
