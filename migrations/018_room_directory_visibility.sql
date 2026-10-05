-- merovingian-migration version=18 name=room_directory_visibility direction=upgrade
-- statement add_room_directory_public_column
ALTER TABLE rooms ADD COLUMN directory_public TEXT NOT NULL DEFAULT 'false'
