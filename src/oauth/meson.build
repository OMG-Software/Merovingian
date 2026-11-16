oauth_sources = files(
  'Pkce.cpp',
  'ScopeParser.cpp',
)

# Pure functions only: no runtime state, no I/O, no logging (src/oauth/AGENTS.md).
oauth_lib = static_library(
  'merovingian-oauth',
  oauth_sources,
  include_directories: inc,
  link_with: [auth_lib, canonicaljson_lib, core_lib, crypto_lib],
)
