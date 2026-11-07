net_sources = files(
  'ConnectionParker.cpp',
  'RuntimeListeners.cpp',
  'loopback_literal.cpp',
  'ShutdownSignal.cpp',
  'TcpAcceptor.cpp',
  'ThreadPool.cpp',
)

net_lib = static_library(
  'merovingian-net',
  net_sources,
  include_directories: inc,
)
