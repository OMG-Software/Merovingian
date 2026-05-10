database_sources = files(
  'connection.cpp',
  'migration.cpp',
  'runtime_database.cpp',
  'schema.cpp',
  'statement.cpp',
)

database_lib = static_library(
  'merovingian-database',
  database_sources,
  include_directories: inc,
)
