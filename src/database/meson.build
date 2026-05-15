database_sources = files(
  'connection.cpp',
  'migration_files.cpp',
  'migration.cpp',
  'persistent_store.cpp',
  'postgresql_store.cpp',
  'runtime_database.cpp',
  'schema.cpp',
  'sqlite_store.cpp',
  'statement.cpp',
)

database_lib = static_library(
  'merovingian-database',
  database_sources,
  include_directories: inc,
  dependencies: [libpq_dep, sqlite_dep],
  link_with: [canonicaljson_lib],
)
