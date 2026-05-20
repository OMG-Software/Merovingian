project('curl-wrap', 'c', meson_version: '>=1.1.0')

external_project = import('unstable-external_project')

curl_project = external_project.add_project(
  'configure',
  configure_options: [
    '--disable-shared',
    '--enable-static',
    # Automake's depcomp bootstrap fails on NTFS-backed filesystems (e.g. WSL
    # builds under /mnt/c/). Dependency tracking is an optimisation that skips
    # unchanged translation units; disabling it causes full rebuilds but does
    # not affect correctness.
    '--disable-dependency-tracking',
    '--without-brotli',
    '--without-zlib',
    '--without-zstd',
    '--without-libpsl',
    '--without-librtmp',
    '--without-libidn2',
    '--without-nghttp2',
    '--without-nghttp3',
    '--without-ngtcp2',
    '--without-quiche',
    '--without-wolfssl',
    '--without-gssapi',
    '--without-libssh2',
    '--with-openssl',
    '--prefix=@PREFIX@',
    '--libdir=@PREFIX@/@LIBDIR@',
    '--includedir=@PREFIX@/@INCLUDEDIR@',
  ],
)

libcurl_dep = curl_project.dependency('curl')
meson.override_dependency('libcurl', libcurl_dep)
