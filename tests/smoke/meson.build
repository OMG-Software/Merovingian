smoke_test = find_program('sh')
server_executable = meson.project_build_root() / 'src' / 'merovingian-server'
example_config = meson.project_source_root() / 'config' / 'merovingian.conf.example'
valid_config = meson.project_build_root() / 'valid-smoke.conf'
invalid_config = meson.project_build_root() / 'invalid-smoke.conf'
oversized_config = meson.project_build_root() / 'oversized-smoke.conf'
unsafe_config = meson.project_build_root() / 'unsafe-smoke.conf'
secure_secret_config = meson.project_build_root() / 'secret-secure-smoke.conf'
unsafe_secret_config = meson.project_build_root() / 'secret-unsafe-smoke.conf'
secure_secret = meson.project_build_root() / 'db-uri-secure-smoke.secret'
unsafe_secret = meson.project_build_root() / 'db-uri-unsafe-smoke.secret'

test(
  'server-help-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' --help 2>&1 | grep -q "Usage:"',
  ],
)

test(
  'server-version-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' --version 2>&1 | grep -q "merovingian-server 0.1.0"',
  ],
)

test(
  'server-invalid-arguments-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' --unknown >/dev/null 2>&1; test $? -eq 64',
  ],
)

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
  'server-default-summary-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' 2>&1 | grep -q "Configuration source: defaults"',
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
  'server-example-config-summary-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable
      + ' --config '
      + example_config
      + ' 2>&1 | grep -q "Configuration source: file"',
  ],
)

test(
  'server-valid-config-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "server.name=matrix.example.org" "server.public_baseurl=https://matrix.example.org" > '
      + valid_config
      + ' && chmod 0644 '
      + valid_config
      + ' && '
      + server_executable
      + ' --config '
      + valid_config
      + ' 2>&1 | grep -q "Server name: matrix.example.org"',
  ],
)

test(
  'server-invalid-config-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "server.public_baseurl=http://matrix.example.org" > '
      + invalid_config
      + ' && chmod 0644 '
      + invalid_config
      + ' && '
      + server_executable
      + ' --config '
      + invalid_config
      + ' >/dev/null 2>&1; test $? -eq 79',
  ],
)

test(
  'server-oversized-config-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'dd if=/dev/zero bs=1048577 count=1 2>/dev/null | tr "\\000" "#" > '
      + oversized_config
      + ' && chmod 0644 '
      + oversized_config
      + ' && '
      + server_executable
      + ' --config '
      + oversized_config
      + ' >/dev/null 2>&1; test $? -eq 78',
  ],
)

test(
  'server-unsafe-config-permissions-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "server.name=matrix.example.org" > '
      + unsafe_config
      + ' && chmod 0664 '
      + unsafe_config
      + ' && '
      + server_executable
      + ' --config '
      + unsafe_config
      + ' >/dev/null 2>&1; test $? -eq 79',
  ],
)

test(
  'server-secure-existing-secret-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "postgresql://merovingian@example.invalid/merovingian" > '
      + secure_secret
      + ' && chmod 0600 '
      + secure_secret
      + ' && printf "%s\n" "database.uri_file='
      + secure_secret
      + '" > '
      + secure_secret_config
      + ' && chmod 0644 '
      + secure_secret_config
      + ' && '
      + server_executable
      + ' --config '
      + secure_secret_config
      + ' 2>&1 | grep -q "Configuration validation passed"',
  ],
)

test(
  'server-unsafe-existing-secret-file-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "postgresql://merovingian@example.invalid/merovingian" > '
      + unsafe_secret
      + ' && chmod 0644 '
      + unsafe_secret
      + ' && printf "%s\n" "database.uri_file='
      + unsafe_secret
      + '" > '
      + unsafe_secret_config
      + ' && chmod 0644 '
      + unsafe_secret_config
      + ' && '
      + server_executable
      + ' --config '
      + unsafe_secret_config
      + ' >/dev/null 2>&1; test $? -eq 79',
  ],
)
