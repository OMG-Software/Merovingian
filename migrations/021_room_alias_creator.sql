-- merovingian-migration version=21 name=room_alias_creator direction=upgrade
-- statement add_room_aliases_creator_user_id_column
ALTER TABLE room_aliases ADD COLUMN creator_user_id TEXT NOT NULL DEFAULT ''
