email_sources = files(
  'mailbox_address.cpp',
  'notification_email.cpp',
  'smtp_client.cpp',
  'smtp_endpoint.cpp',
)

email_lib = static_library(
  'merovingian-email',
  email_sources,
  include_directories: inc,
  dependencies: [libcurl_dep],
  link_with: [core_lib, http_lib, platform_lib],
)
