smoke_test = find_program('sh')

test(
  'server-bootstrap-smoke-test',
  smoke_test,
  args: [
    '-c',
    './merovingian-server >/dev/null 2>&1',
  ],
  workdir: meson.current_build_dir() / '..' / 'src',
)
