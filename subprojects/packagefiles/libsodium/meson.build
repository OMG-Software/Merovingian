project('libsodium-wrap', 'c', meson_version: '>=1.1.0')

external_project = import('unstable-external_project')

libsodium_project = external_project.add_project(
  'configure',
  configure_options: [
    '--disable-shared',
    '--enable-static',
    '--prefix=@PREFIX@',
    '--libdir=@PREFIX@/@LIBDIR@',
    '--includedir=@PREFIX@/@INCLUDEDIR@',
  ],
)

libsodium_dep = libsodium_project.dependency('sodium')
meson.override_dependency('libsodium', libsodium_dep)
