-- merovingian-migration version=7 name=account_threepids_columns direction=upgrade
-- statement add_client_secret_column
ALTER TABLE account_threepids ADD COLUMN client_secret TEXT NOT NULL DEFAULT ''
-- statement add_sid_column
ALTER TABLE account_threepids ADD COLUMN sid TEXT NOT NULL DEFAULT ''
