platform_sources = files(
  'elf_probe.cpp',
  'file_metadata.cpp',
  'hardening_self_check.cpp',
  'landlock_hardening.cpp',
  'runtime_hardening.cpp',
  'seccomp_hardening.cpp',
  'signal_hardening.cpp',
)

platform_lib = static_library(
  'merovingian-platform',
  platform_sources,
  include_directories: inc,
)
