#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/validate-phase1-config.sh <build-dir>" >&2
  exit 2
fi

build_dir="$1"
server="${build_dir}/src/merovingian-server"
example_config="config/merovingian.conf.example"
invalid_config="${build_dir}/invalid-phase1-config.conf"

if [[ ! -x "${server}" ]]; then
  echo "server executable not found: ${server}" >&2
  exit 1
fi

"${server}" --dry-run >/dev/null
"${server}" --dry-run --config "${example_config}" >/dev/null

printf '%s\n' \
  'server.public_baseurl=http://matrix.example.org' \
  'listeners.client.bind=0.0.0.0:8008' \
  > "${invalid_config}"

if "${server}" --dry-run --config "${invalid_config}" >/dev/null 2>&1; then
  echo "invalid Phase 1 config was accepted" >&2
  exit 1
fi
