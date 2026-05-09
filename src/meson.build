subdir('core')
subdir('config')
subdir('net')

executable(
  'merovingian-server',
  sources: files('main.cpp'),
  include_directories: inc,
  dependencies: [thread_dep],
  link_with: [core_lib, config_lib, net_lib],
  install: true,
)
