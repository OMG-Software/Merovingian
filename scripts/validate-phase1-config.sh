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
  "${build_dir}/subprojects/curl-8.23.0/dist/usr/local/lib"
  "${build_dir}/subprojects/curl-8.23.0/dist/usr/local/lib64"
  "${build_dir}/subprojects/curl-8.23.0/dist/usr/local/lib/x86_64-linux-gnu"
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

# The example sets security.secrets.master_key_file, and a configured master key
# that is missing fails --dry-run. Provision one the way an operator would
# (owner-only, 0400) and validate a copy of the example that points at it; every
# other line is validated as shipped.
workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
master_key="${workdir}/master-key"
(umask 077 && dd if=/dev/urandom of="${master_key}" bs=32 count=1 2>/dev/null)
chmod 0400 "${master_key}"
keyed_example_config="${workdir}/merovingian.conf.example"
sed "s|^security.secrets.master_key_file=.*|security.secrets.master_key_file=${master_key}|" \
  "${example_config}" > "${keyed_example_config}"
"${server}" --dry-run --config "${keyed_example_config}" >/dev/null

printf '%s\n' \
  'server.public_baseurl=http://matrix.example.org' \
  'listeners.client.bind=0.0.0.0:8008' \
  > "${invalid_config}"

if "${server}" --dry-run --config "${invalid_config}" >/dev/null 2>&1; then
  echo "invalid Phase 1 config was accepted" >&2
  exit 1
fi
