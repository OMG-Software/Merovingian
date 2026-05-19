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
runtime_library_dirs=(
  "${build_dir}/subprojects/libsodium-1.0.22/dist/usr/local/lib"
  "${build_dir}/subprojects/libsodium-1.0.22/dist/usr/local/lib64"
  "${build_dir}/subprojects/libsodium-1.0.22/dist/usr/local/lib/x86_64-linux-gnu"
  "${build_dir}/subprojects/postgresql-18.0/dist/usr/local/lib"
  "${build_dir}/subprojects/postgresql-18.0/dist/usr/local/lib64"
  "${build_dir}/subprojects/postgresql-18.0/dist/usr/local/lib/x86_64-linux-gnu"
  "${build_dir}/subprojects/curl-8.20.0/dist/usr/local/lib"
  "${build_dir}/subprojects/curl-8.20.0/dist/usr/local/lib64"
  "${build_dir}/subprojects/curl-8.20.0/dist/usr/local/lib/x86_64-linux-gnu"
)

if [[ ! -x "${server}" ]]; then
  echo "server executable not found: ${server}" >&2
  exit 1
fi

for runtime_library_dir in "${runtime_library_dirs[@]}"; do
  if [[ -d "${runtime_library_dir}" ]]; then
    LD_LIBRARY_PATH="${runtime_library_dir}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
  fi
done
export LD_LIBRARY_PATH

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
