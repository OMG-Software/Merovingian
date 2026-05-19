project(
  'merovingian',
  'cpp',
  'c',
  version: '0.2.1',
  license: 'GPL-3.0-or-later',
  meson_version: '>=1.1.0',
  default_options: [
    'cpp_std=c++26',
    'warning_level=3',
    'werror=true',
  ],
)

cpp = meson.get_compiler('cpp')
thread_dep = dependency('threads')
libsodium_dep = dependency('libsodium', include_type: 'system', allow_fallback: false)
openssl_dep = dependency('openssl', include_type: 'system', allow_fallback: false)
# pgcommon and pgport are internal PostgreSQL libraries that libpq.a requires
# when linked statically but that Alpine's libpq.pc omits from Libs.private.
# Wrapping them here ensures they are always available when needed without
# affecting dynamic builds (find_library returns an empty dep when absent).
_libpq      = dependency('libpq', include_type: 'system', allow_fallback: false)
_pgcommon   = cpp.find_library('pgcommon', required: false)
_pgport     = cpp.find_library('pgport',   required: false)
libpq_dep   = declare_dependency(dependencies: [_libpq, _pgcommon, _pgport])
sqlite_dep = dependency(
  'sqlite3',
  fallback: ['sqlite3', 'sqlite3_dep'],
  default_options: ['default_library=static'],
)
yyjson_dep = dependency(
  'yyjson',
  version: '>=0.12.0',
  required: false,
  fallback: ['yyjson', 'yyjson_dep'],
)
# libcurl drives the federation outbound HTTP client. The TLS backend is
# whatever the system libcurl was built against; the OutboundClient
# integration suite enforces consistent verification behavior across
# Linux and BSD targets. A subprojects/curl.wrap fallback builds curl
# from source when the system library is not available.
libcurl_dep = dependency('libcurl', fallback: ['curl', 'libcurl_dep'])
resolv_dep = cpp.find_library('resolv', required: false)

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
  '-Wno-c2y-extensions',
]

hardening_compile_flags = [
  '-fstack-protector-strong',
  '-fPIE',
  '-fvisibility=hidden',
  '-ftrivial-auto-var-init=zero',
  '-fstack-clash-protection',
  '-fcf-protection=full',
]

# -pie is supplied per-platform by the build scripts:
#   Alpine/musl .deb → -static-pie (fully static PIE via cpp_link_args)
#   Fedora .rpm / FreeBSD .pkg → -pie (dynamic-libc PIE via cpp_link_args)
# -Wl,-z,relro/-z,now are enforced by the dynamic linker; omitted here because
# fully-static binaries have no dynamic linker to enforce them.
# -Wl,-z,noexecstack sets the PT_GNU_STACK ELF note; the kernel reads this on
# both static and dynamic ELF binaries, so it applies universally.
hardening_link_flags = [
  '-Wl,-z,noexecstack',
]

add_project_arguments(cpp.get_supported_arguments(warning_flags), language: 'cpp')

if get_option('hardening')
  if get_option('optimization') != '0'
    hardening_compile_flags += ['-D_FORTIFY_SOURCE=3']
  endif
  add_project_arguments(cpp.get_supported_arguments(hardening_compile_flags), language: 'cpp')
  add_project_link_arguments(cpp.get_supported_link_arguments(hardening_link_flags), language: 'cpp')
endif

inc = include_directories('include')

subdir('src')
subdir('tests')
