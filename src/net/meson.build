net_sources = files(
  'connection_parker.cpp',
  'listener.cpp',
  'loopback_literal.cpp',
  'shutdown_signal.cpp',
  'tcp_acceptor.cpp',
  'thread_pool.cpp',
)

net_lib = static_library(
  'merovingian-net',
  net_sources,
  include_directories: inc,
)
