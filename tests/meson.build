if get_option('build_tests')
  catch2_dep = dependency(
    'catch2',
    required: false,
    fallback: ['catch2', 'catch2_dep'],
  )

  unit_test_registration_check = find_program('../scripts/check-unit-test-registration.sh')
  test(
    'unit-test-registration',
    unit_test_registration_check,
    args: [meson.project_source_root()],
  )

  catch2_bdd_check = find_program('../scripts/check-catch2-bdd-tests.sh')
  test(
    'catch2-bdd-tests',
    catch2_bdd_check,
    args: [meson.project_source_root()],
  )

  unit_tests = executable(
    'merovingian-unit-tests',
    sources: files(
      'unit/test_main.cpp',
      'unit/test_auth.cpp',
      'unit/test_auth_client_server_api.cpp',
      'unit/test_auth_session.cpp',
      'unit/test_canonicaljson_parser.cpp',
      'unit/test_canonicaljson_serializer.cpp',
      'unit/test_client_server_mvp.cpp',
      'unit/test_config_defaults.cpp',
      'unit/test_config_media_timeout.cpp',
      'unit/test_config_parser.cpp',
      'unit/test_config_reload_plan.cpp',
      'unit/test_config_reload_policy.cpp',
      'unit/test_crypto.cpp',
      'unit/test_database_backend_config.cpp',
      'unit/test_database_persistence.cpp',
      'unit/test_event_authorization.cpp',
      'unit/test_events.cpp',
      'unit/test_federation_inbound_request.cpp',
      'unit/test_federation_security.cpp',
      'unit/test_federation_transactions.cpp',
      'unit/test_file_descriptor.cpp',
      'unit/test_file_metadata.cpp',
      'unit/test_hardening_self_check.cpp',
      'unit/test_homeserver_vertical_slice.cpp',
      'unit/test_http_connection_guard.cpp',
      'unit/test_http_rate_limit.cpp',
      'unit/test_http_request.cpp',
      'unit/test_http_request_limits.cpp',
      'unit/test_key_api.cpp',
      'unit/test_media_repository.cpp',
      'unit/test_media_security.cpp',
      'unit/test_not_null.cpp',
      'unit/test_observability.cpp',
      'unit/test_review_regressions.cpp',
      'unit/test_room_encryption_policy.cpp',
      'unit/test_runtime_config.cpp',
      'unit/test_runtime_database.cpp',
      'unit/test_runtime_federation.cpp',
      'unit/test_runtime_hardening.cpp',
      'unit/test_runtime_listeners.cpp',
      'unit/test_runtime_media.cpp',
      'unit/test_secret_buffer.cpp',
      'unit/test_shutdown_signal.cpp',
      'unit/test_state_resolution.cpp',
      'unit/test_tcp_acceptor.cpp',
      'unit/test_trust_safety_policy.cpp',
    ),
    include_directories: inc,
    dependencies: [catch2_dep, thread_dep],
    link_with: [auth_lib, canonicaljson_lib, core_lib, config_lib, crypto_lib, database_lib, events_lib, federation_lib, homeserver_lib, http_lib, media_lib, net_lib, observability_lib, platform_lib, rooms_lib, trust_safety_lib],
  )

  test('unit-tests', unit_tests)

  integration_tests = executable(
    'merovingian-integration-tests',
    sources: files(
      'integration/test_main.cpp',
      'integration/test_client_server_mvp_flow.cpp',
      'integration/test_federation_inbound_flow.cpp',
      'integration/test_homeserver_vertical_slice_flow.cpp',
      'integration/test_http_server_listener_flow.cpp',
      'integration/test_media_repository_security.cpp',
      'integration/test_observability_flow.cpp',
      'integration/test_persistent_homeserver_flow.cpp',
      'integration/test_runtime_hardening_flow.cpp',
      'integration/test_trust_safety_policy_flow.cpp',
    ),
    include_directories: inc,
    dependencies: [catch2_dep, thread_dep],
    link_with: [auth_lib, canonicaljson_lib, core_lib, config_lib, crypto_lib, database_lib, events_lib, federation_lib, homeserver_lib, http_lib, media_lib, net_lib, observability_lib, platform_lib, rooms_lib, trust_safety_lib],
  )

  test('integration-tests', integration_tests)

  subdir('smoke')
endif

if get_option('build_fuzz')
  subdir('fuzz')
endif
