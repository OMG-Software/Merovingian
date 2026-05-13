-- merovingian-migration version=1 name=initial_schema direction=upgrade
-- statement create_schema_migrations
CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, name TEXT NOT NULL, direction TEXT NOT NULL)
