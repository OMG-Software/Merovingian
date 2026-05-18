project('libpq-wrap', 'c', meson_version: '>=1.1.0')

external_project = import('unstable-external_project')

libpq_project = external_project.add_project(
  'configure',
  configure_options: [
    '--disable-shared',
    '--enable-static',
    '--without-bonjour',
    '--without-gssapi',
    '--without-icu',
    '--without-ldap',
    '--without-libcurl',
    '--without-libxml',
    '--without-libxslt',
    '--without-lz4',
    '--without-pam',
    '--without-perl',
    '--without-python',
    '--without-readline',
    '--without-selinux',
    '--without-systemd',
    '--without-tcl',
    '--without-zlib',
    '--without-zstd',
    '--with-openssl',
    '--prefix=@PREFIX@',
    '--libdir=@PREFIX@/@LIBDIR@',
    '--includedir=@PREFIX@/@INCLUDEDIR@',
  ],
)

libpq_dep = libpq_project.dependency('pq', subdir: 'postgresql')
meson.override_dependency('libpq', libpq_dep)
