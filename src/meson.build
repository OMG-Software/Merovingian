subdir('core')

executable(
  'merovingian-server',
  sources: files('main.cpp'),
  include_directories: inc,
  dependencies: [thread_dep],
  link_with: [core_lib],
  install: true,
)
