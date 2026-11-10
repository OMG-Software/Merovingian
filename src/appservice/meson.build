appservice_sources = files(
  'AppserviceClient.cpp',
  'AppserviceRegistry.cpp',
  'Namespace.cpp',
  'CleartextPolicy.cpp',
  'MasqueradeToken.cpp',
  'Registration.cpp',
  'RegistrationYaml.cpp',
)

appservice_lib = static_library(
  'merovingian-appservice',
  appservice_sources,
  include_directories: inc,
)
