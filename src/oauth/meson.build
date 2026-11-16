oauth_sources = files(
  'AccountPages.cpp',
  'AsciiCase.cpp',
  'AuthorizationPages.cpp',
  'AuthorizationRedirect.cpp',
  'ClientMetadata.cpp',
  'ClientUri.cpp',
  'DisplayText.cpp',
  'FormContentType.cpp',
  'FormPostOrigin.cpp',
  'HandOffAllowlist.cpp',
  'HtmlText.cpp',
  'OAuthBaseUrl.cpp',
  'Page.cpp',
  'PageForm.cpp',
  'PageHeaders.cpp',
  'ParsedUri.cpp',
  'Pkce.cpp',
  'RedirectUriRules.cpp',
  'ScopeParser.cpp',
  'ServerMetadata.cpp',
)

# Pure functions only: no runtime state, no I/O, no logging (src/oauth/AGENTS.md).
oauth_lib = static_library(
  'merovingian-oauth',
  oauth_sources,
  include_directories: inc,
  link_with: [auth_lib, canonicaljson_lib, core_lib, crypto_lib],
)
