if get_option('build_tests')
  catch2_dep = dependency(
    'catch2',
    required: false,
    fallback: ['catch2', 'catch2_dep'],
  )

  unit_tests = executable(
    'merovingian-unit-tests',
    sources: files(
      'unit/test_main.cpp',
      'unit/test_config_defaults.cpp',
      'unit/test_config_media_timeout.cpp',
      'unit/test_config_parser.cpp',
      'unit/test_config_reload_plan.cpp',
      'unit/test_config_reload_policy.cpp',
      'unit/test_file_descriptor.cpp',
      'unit/test_file_metadata.cpp',
      'unit/test_hardening_self_check.cpp',
      'unit/test_http_connection_guard.cpp',
      'unit/test_http_rate_limit.cpp',
      'unit/test_http_request.cpp',
      'unit/test_http_request_limits.cpp',
      'unit/test_not_null.cpp',
      'unit/test_runtime_config.cpp',
      'unit/test_runtime_database.cpp',
      'unit/test_runtime_federation.cpp',
      'unit/test_runtime_listeners.cpp',
      'unit/test_runtime_media.cpp',
      'unit/test_secret_buffer.cpp',
    ),
    include_directories: inc,
    dependencies: [catch2_dep, thread_dep],
    link_with: [core_lib, config_lib, database_lib, federation_lib, http_lib, media_lib, net_lib, platform_lib],
  )

  test('unit-tests', unit_tests)

  subdir('smoke')
endif

if get_option('build_fuzz')
  subdir('fuzz')
endif
