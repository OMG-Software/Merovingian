-- merovingian-migration version=14 name=user_deactivation direction=upgrade
-- statement add_deactivated_column
ALTER TABLE users ADD COLUMN deactivated TEXT NOT NULL DEFAULT 'false'
