smoke_test = find_program('sh')
server_executable = meson.project_build_root() / 'src' / 'merovingian-server'
example_config = meson.project_source_root() / 'config' / 'merovingian.conf.example'
valid_config = meson.project_build_root() / 'valid-smoke.conf'
invalid_config = meson.project_build_root() / 'invalid-smoke.conf'
oversized_config = meson.project_build_root() / 'oversized-smoke.conf'

test(
  'server-bootstrap-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' >/dev/null 2>&1',
  ],
)

test(
  'server-config-validation-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' 2>&1 | grep -q "Configuration validation passed"',
  ],
)

test(
  'server-example-config-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable
      + ' --config '
      + example_config
      + ' 2>&1 | grep -q "Configuration validation passed"',
  ],
)

test(
  'server-valid-config-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "server.name=matrix.example.org" "server.public_baseurl=https://matrix.example.org" > '
      + valid_config
      + ' && '
      + server_executable
      + ' --config '
      + valid_config
      + ' 2>&1 | grep -q "Configuration validation passed"',
  ],
)

test(
  'server-invalid-config-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "server.public_baseurl=http://matrix.example.org" > '
      + invalid_config
      + ' && ! '
      + server_executable
      + ' --config '
      + invalid_config
      + ' >/dev/null 2>&1',
  ],
)

test(
  'server-oversized-config-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'python3 -c "from pathlib import Path; Path(\''
      + oversized_config
      + '\').write_text(\'#\' * (1024 * 1024 + 1))" && ! '
      + server_executable
      + ' --config '
      + oversized_config
      + ' >/dev/null 2>&1',
  ],
)
