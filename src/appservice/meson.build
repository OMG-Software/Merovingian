appservice_sources = files(
  'AppserviceClient.cpp',
  'masquerade_token.cpp',
  'registration.cpp',
  'registration_yaml.cpp',
)

appservice_lib = static_library(
  'merovingian-appservice',
  appservice_sources,
  include_directories: inc,
)
