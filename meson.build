project(
  'the-merovingian',
  'cpp',
  version: '0.1.3',
  license: 'GPL-3.0-or-later',
  meson_version: '>=1.1.0',
  default_options: [
    'cpp_std=c++26',
    'warning_level=3',
    'werror=true',
    'b_pie=true',
  ],
)

cpp = meson.get_compiler('cpp')
thread_dep = dependency('threads')
libsodium_dep = dependency('libsodium')

warning_flags = [
  '-Wall',
  '-Wextra',
  '-Wpedantic',
  '-Wconversion',
  '-Wsign-conversion',
  '-Wshadow',
  '-Wnon-virtual-dtor',
  '-Wold-style-cast',
  '-Wcast-align',
  '-Wunused',
  '-Woverloaded-virtual',
  '-Wnull-dereference',
  '-Wdouble-promotion',
  '-Wformat=2',
  '-Wimplicit-fallthrough',
]

hardening_compile_flags = [
  '-fstack-protector-strong',
  '-D_FORTIFY_SOURCE=3',
  '-fPIE',
  '-fvisibility=hidden',
  '-ftrivial-auto-var-init=zero',
  '-fstack-clash-protection',
  '-fcf-protection=full',
]

hardening_link_flags = [
  '-pie',
  '-Wl,-z,relro',
  '-Wl,-z,now',
  '-Wl,-z,noexecstack',
]

add_project_arguments(cpp.get_supported_arguments(warning_flags), language: 'cpp')

if get_option('hardening')
  add_project_arguments(cpp.get_supported_arguments(hardening_compile_flags), language: 'cpp')
  add_project_link_arguments(cpp.get_supported_link_arguments(hardening_link_flags), language: 'cpp')
endif

inc = include_directories('include')

subdir('src')
subdir('tests')
