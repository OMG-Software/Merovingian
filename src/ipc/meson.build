ipc_lib = static_library(
  'merovingian-ipc',
  sources: files('channel.cpp', 'ipc_ed25519_provider.cpp', 'federation_ipc_frames.cpp'),
  include_directories: inc,
  dependencies: [libsodium_dep, thread_dep],
)
