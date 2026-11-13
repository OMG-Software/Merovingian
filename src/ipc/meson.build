ipc_lib = static_library(
  'merovingian-ipc',
  sources: files('IpcChannel.cpp', 'FederationIpcFrames.cpp', 'RoomSnapshotAssembler.cpp'),
  include_directories: inc,
  dependencies: [libsodium_dep, thread_dep],
)
