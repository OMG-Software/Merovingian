platform_sources = files(
  'ElfProbe.cpp',
  'FileMetadataSupport.cpp',
  'HardeningSelfCheck.cpp',
  'LandlockHardening.cpp',
  'RuntimeHardening.cpp',
  'SeccompHardening.cpp',
  'SignalHardening.cpp',
)

platform_lib = static_library(
  'merovingian-platform',
  platform_sources,
  include_directories: inc,
)
