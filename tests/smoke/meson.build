smoke_test = find_program('sh')
server_executable = meson.project_build_root() / 'src' / 'merovingian-server'

test(
  'server-bootstrap-smoke-test',
  smoke_test,
  args: [
    '-c',
    server_executable + ' >/dev/null 2>&1',
  ],
)
