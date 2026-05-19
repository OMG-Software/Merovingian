project('openssl-wrap', 'c', meson_version: '>=1.1.0')

external_project = import('unstable-external_project')

openssl_project = external_project.add_project(
  'configure-wrapper.sh',
  configure_options: [
    '--prefix=@PREFIX@',
    'no-shared',
    'no-tests',
    'no-external-tests',
    'no-autoload-config',
  ],
)

libcrypto_dep = openssl_project.dependency('crypto', subdir: 'openssl')
libssl_dep = openssl_project.dependency('ssl', subdir: 'openssl')
openssl_dep = declare_dependency(
  dependencies: [libcrypto_dep, libssl_dep],
)

meson.override_dependency('libcrypto', libcrypto_dep)
meson.override_dependency('libssl', libssl_dep)
meson.override_dependency('openssl', openssl_dep)
