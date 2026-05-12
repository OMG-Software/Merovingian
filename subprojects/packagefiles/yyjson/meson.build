project(
  'yyjson',
  'c',
  version: '0.12.0',
  license: 'MIT',
  meson_version: '>=1.1.0',
  default_options: [
    'warning_level=2',
  ],
)

yyjson_inc = include_directories('src')

yyjson_lib = static_library(
  'yyjson',
  sources: files('src/yyjson.c'),
  include_directories: yyjson_inc,
)

yyjson_dep = declare_dependency(
  include_directories: yyjson_inc,
  link_with: yyjson_lib,
)
