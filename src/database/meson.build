database_sources = files(
  'connection.cpp',
  'event_table.cpp',
  'EventStateGroupTable.cpp',
  'library_versions.cpp',
  'migration_files.cpp',
  'migration.cpp',
  'PersistentStore.cpp',
  'PersistentServerSigningKey.cpp',
  'PostgresqlConnectionDeleter.cpp',
  'redaction_view.cpp',
  'postgresql_store.cpp',
  'runtime_database.cpp',
  'schema.cpp',
  'sqlite_store.cpp',
  'SqliteConnectionDeleter.cpp',
  'StateGroupEntryTable.cpp',
  'StateGroupTable.cpp',
  'statement.cpp',
)

database_lib = static_library(
  'merovingian-database',
  database_sources,
  include_directories: inc,
  dependencies: [libpq_dep, sqlite_dep],
  link_with: [canonicaljson_lib],
  cpp_args: ['-DMEROVINGIAN_LIBPQ_BUILD_VERSION="' + libpq_build_version + '"'],
)
