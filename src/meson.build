subdir('core')
subdir('config')

executable(
  'merovingian-server',
  sources: files('main.cpp'),
  include_directories: inc,
  dependencies: [thread_dep],
  link_with: [core_lib, config_lib],
  install: true,
)
