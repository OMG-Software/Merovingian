email_sources = files(
  'MailboxAddress.cpp',
  'NotificationEmail.cpp',
  'SmtpClient.cpp',
  'SmtpEndpoint.cpp',
)

email_lib = static_library(
  'merovingian-email',
  email_sources,
  include_directories: inc,
  dependencies: [libcurl_dep],
  link_with: [core_lib, http_lib, net_lib, platform_lib],
)
