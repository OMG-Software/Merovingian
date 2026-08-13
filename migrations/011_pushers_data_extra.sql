-- merovingian-migration version=11 name=pushers_data_extra direction=upgrade
-- statement add_data_extra_json_column
ALTER TABLE pushers ADD COLUMN data_extra_json TEXT NOT NULL DEFAULT ''
