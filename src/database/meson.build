database_sources = files(
  'connection.cpp',
  'migration.cpp',
  'persistent_store.cpp',
  'runtime_database.cpp',
  'schema.cpp',
  'sqlite_store.cpp',
  'statement.cpp',
)

database_lib = static_library(
  'merovingian-database',
  database_sources,
  include_directories: inc,
  dependencies: [sqlite_dep],
)
