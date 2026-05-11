smoke_test = find_program('sh')
server_executable = meson.project_build_root() / 'src' / 'merovingian-server'
setup_dev_env_script = meson.project_source_root() / 'scripts' / 'setup-dev-env.sh'
example_config = meson.project_source_root() / 'config' / 'merovingian.conf.example'
valid_config = meson.project_build_root() / 'valid-smoke.conf'
check_config = meson.project_build_root() / 'check-smoke.conf'
noop_reload_current_config = meson.project_build_root() / 'noop-reload-current-smoke.conf'
noop_reload_next_config = meson.project_build_root() / 'noop-reload-next-smoke.conf'
reloadable_current_config = meson.project_build_root() / 'reloadable-current-smoke.conf'
reloadable_next_config = meson.project_build_root() / 'reloadable-next-smoke.conf'
restart_current_config = meson.project_build_root() / 'restart-current-smoke.conf'
restart_next_config = meson.project_build_root() / 'restart-next-smoke.conf'
invalid_reload_current_config = meson.project_build_root() / 'invalid-reload-current-smoke.conf'
invalid_reload_next_config = meson.project_build_root() / 'invalid-reload-next-smoke.conf'
invalid_current_reload_config = meson.project_build_root() / 'invalid-current-reload-smoke.conf'
valid_next_reload_config = meson.project_build_root() / 'valid-next-reload-smoke.conf'
invalid_config = meson.project_build_root() / 'invalid-smoke.conf'
oversized_config = meson.project_build_root() / 'oversized-smoke.conf'
unsafe_config = meson.project_build_root() / 'unsafe-smoke.conf'
secure_secret_config = meson.project_build_root() / 'secret-secure-smoke.conf'
unsafe_secret_config = meson.project_build_root() / 'secret-unsafe-smoke.conf'
redaction_config = meson.project_build_root() / 'redaction-smoke.conf'
redaction_secret = meson.project_build_root() / 'db-uri-redaction-smoke.secret'
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
  'setup-dev-env-help-smoke-test',
  smoke_test,
  args: [
    '-c',
    'sh ' + setup_dev_env_script + ' --help 2>&1 | grep -q "Usage:"',
  ],
)

test(
  'setup-dev-env-linux-dry-run-smoke-test',
  smoke_test,
  args: [
    '-c',
    'sh '
      + setup_dev_env_script
      + ' --dry-run --no-configure 2>&1 | grep -q "apt-get install -y"',
  ],
  env: {
    'MEROVINGIAN_SETUP_OS': 'Linux',
    'MEROVINGIAN_SETUP_PACKAGE_MANAGER': 'apt',
  },
)

test(
  'setup-dev-env-freebsd-dry-run-smoke-test',
  smoke_test,
  args: [
    '-c',
    'sh '
      + setup_dev_env_script
      + ' --dry-run --no-configure 2>&1 | grep -q "pkg install -y"',
  ],
  env: {
    'MEROVINGIAN_SETUP_OS': 'FreeBSD',
    'MEROVINGIAN_SETUP_PACKAGE_MANAGER': 'pkg',
  },
)

test(
  'setup-dev-env-openbsd-dry-run-smoke-test',
  smoke_test,
  args: [
    '-c',
    'sh '
      + setup_dev_env_script
      + ' --dry-run --no-configure 2>&1 | grep -q "pkg_add"',
  ],
  env: {
    'MEROVINGIAN_SETUP_OS': 'OpenBSD',
    'MEROVINGIAN_SETUP_PACKAGE_MANAGER': 'pkg_add',
  },
)

test(
  'setup-dev-env-netbsd-dry-run-smoke-test',
  smoke_test,
  args: [
    '-c',
    'sh '
      + setup_dev_env_script
      + ' --dry-run --no-configure 2>&1 | grep -q "pkgin -y install"',
  ],
  env: {
    'MEROVINGIAN_SETUP_OS': 'NetBSD',
    'MEROVINGIAN_SETUP_PACKAGE_MANAGER': 'pkgin',
  },
)

test(
  'server-version-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' --version 2>&1 | grep -q "merovingian-server 0.1.2"',
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
  'server-hardening-self-check-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' 2>&1 | grep -q "Startup hardening checks:" && '
      + server_executable + ' 2>&1 | grep -q "Hardening self-check: seccomp=unknown"',
  ],
)

test(
  'server-check-config-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable
      + ' --check-config '
      + example_config
      + ' 2>&1 | grep -q "Configuration check passed:"',
  ],
)

test(
  'server-check-config-does-not-start-runtime-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable
      + ' --check-config '
      + example_config
      + ' 2>&1 | grep -vq "Starting The Merovingian bootstrap server"',
  ],
)

test(
  'server-check-invalid-config-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "server.public_baseurl=http://matrix.example.org" > '
      + check_config
      + ' && chmod 0644 '
      + check_config
      + ' && '
      + server_executable
      + ' --check-config '
      + check_config
      + ' >/dev/null 2>&1; test $? -eq 79',
  ],
)

test(
  'server-plan-config-reload-noop-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "security.federation.remote_timeout=30s" > '
      + noop_reload_current_config
      + ' && chmod 0644 '
      + noop_reload_current_config
      + ' && printf "%s\n" "security.federation.remote_timeout=30s" > '
      + noop_reload_next_config
      + ' && chmod 0644 '
      + noop_reload_next_config
      + ' && output=$( '
      + server_executable
      + ' --plan-config-reload '
      + noop_reload_current_config
      + ' '
      + noop_reload_next_config
      + ' 2>&1 ) && echo "$output" | grep -q "Reload plan: changes=0 reloadable=0 restart_required=0" && echo "$output" | grep -q "Reload action: no changes"',
  ],
)

test(
  'server-plan-config-reload-reloadable-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "security.federation.remote_timeout=30s" > '
      + reloadable_current_config
      + ' && chmod 0644 '
      + reloadable_current_config
      + ' && printf "%s\n" "security.federation.remote_timeout=45s" > '
      + reloadable_next_config
      + ' && chmod 0644 '
      + reloadable_next_config
      + ' && output=$( '
      + server_executable
      + ' --plan-config-reload '
      + reloadable_current_config
      + ' '
      + reloadable_next_config
      + ' 2>&1 ) && echo "$output" | grep -q "Reload plan: changes=1 reloadable=1 restart_required=0" && echo "$output" | grep -q "Reload action: reloadable"',
  ],
)

test(
  'server-plan-config-reload-restart-required-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "server.name=example.org" > '
      + restart_current_config
      + ' && chmod 0644 '
      + restart_current_config
      + ' && printf "%s\n" "server.name=new.example.org" > '
      + restart_next_config
      + ' && chmod 0644 '
      + restart_next_config
      + ' && output=$( '
      + server_executable
      + ' --plan-config-reload '
      + restart_current_config
      + ' '
      + restart_next_config
      + ' 2>&1 ) && echo "$output" | grep -q "server.name=restart_required" && echo "$output" | grep -q "Reload action: restart required"',
  ],
)

test(
  'server-plan-config-reload-invalid-next-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "security.federation.remote_timeout=30s" > '
      + invalid_reload_current_config
      + ' && chmod 0644 '
      + invalid_reload_current_config
      + ' && printf "%s\n" "security.federation.remote_timeout=forever" > '
      + invalid_reload_next_config
      + ' && chmod 0644 '
      + invalid_reload_next_config
      + ' && '
      + server_executable
      + ' --plan-config-reload '
      + invalid_reload_current_config
      + ' '
      + invalid_reload_next_config
      + ' >/dev/null 2>&1; test $? -eq 79',
  ],
)

test(
  'server-plan-config-reload-invalid-current-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "security.federation.remote_timeout=forever" > '
      + invalid_current_reload_config
      + ' && chmod 0644 '
      + invalid_current_reload_config
      + ' && printf "%s\n" "security.federation.remote_timeout=30s" > '
      + valid_next_reload_config
      + ' && chmod 0644 '
      + valid_next_reload_config
      + ' && '
      + server_executable
      + ' --plan-config-reload '
      + invalid_current_reload_config
      + ' '
      + valid_next_reload_config
      + ' >/dev/null 2>&1; test $? -eq 79',
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

test(
  'server-database-summary-redaction-smoke-test',
  smoke_test,
  args: [
    '-c',
    'printf "%s\n" "postgresql://merovingian:topsecret@example.invalid/merovingian" > '
      + redaction_secret
      + ' && chmod 0600 '
      + redaction_secret
      + ' && printf "%s\n" "database.uri_file='
      + redaction_secret
      + '" > '
      + redaction_config
      + ' && chmod 0644 '
      + redaction_config
      + ' && output=$( '
      + server_executable
      + ' --config '
      + redaction_config
      + ' 2>&1 ) && echo "$output" | grep -q "Database URI source file configured; pool_size=16" && ! echo "$output" | grep -q "topsecret" && ! echo "$output" | grep -q "postgresql://" && ! echo "$output" | grep -q "'
      + redaction_secret
      + '"',
  ],
)
