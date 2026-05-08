if get_option('build_tests')
  catch2_dep = dependency(
    'catch2-with-main',
    required: false,
    fallback: ['catch2', 'catch2_with_main_dep'],
  )

  unit_tests = executable(
    'merovingian-unit-tests',
    sources: files(
      'unit/test_file_descriptor.cpp',
      'unit/test_not_null.cpp',
      'unit/test_secret_buffer.cpp',
    ),
    include_directories: inc,
    dependencies: [catch2_dep],
    link_with: [core_lib],
  )

  test('unit-tests', unit_tests)

  subdir('smoke')
endif

if get_option('build_fuzz')
  subdir('fuzz')
endif
