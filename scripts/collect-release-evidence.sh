#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Collect release evidence for one platform's hardened build and append it as
# a Markdown section to the given output file. Run once per platform build
# job in .github/workflows/release.yml; the release-notes step in
# publish-alpha-release then concatenates every platform's evidence file into
# the published release notes.
#
# Captures (docs/todos/production-milestone.md "Record compiler version,
# linker flags, dependency versions, test logs, sanitizer logs, fuzz target
# names, package checksums, and GPG signatures in release notes."):
#   - compiler version (CC/CXX as actually invoked)
#   - link-time hardening flags applied (from the hardened profile) and their
#     ELF-level confirmation via scripts/check-elf-hardening.sh
#   - pinned dependency versions (subprojects/*.wrap)
#   - test log summary (Ok/Fail/Timeout counts from meson-logs/testlog.txt)
#   - fuzz target names covered by the mandatory fuzz gate (.github/workflows/fuzz.yml)
#
# Package checksums and GPG signatures are already produced by the packaging
# steps themselves (sha256sum / sign-artifacts.yml) and are listed separately
# in the release notes by the publish job, which has direct access to the
# staged, signed asset files this script cannot see at build time.

set -eu

if [ "$#" -ne 3 ]; then
    printf 'usage: sh scripts/collect-release-evidence.sh <platform-label> <build-dir> <output-file>\n' >&2
    exit 2
fi

platform_label=$1
build_dir=$2
output_file=$3

cc_cmd=${CC:-cc}
cxx_cmd=${CXX:-c++}

{
    printf '### %s\n\n' "$platform_label"

    printf '**Compiler**\n\n'
    printf '```\n'
    "$cxx_cmd" --version 2>&1 | head -n 1 || printf 'unknown (%s --version failed)\n' "$cxx_cmd"
    printf '```\n\n'

    printf '**Link-time hardening**\n\n'
    printf -- '- Profile: `hardened` (`--buildtype=release -Dhardening=true`; see scripts/build-linux.sh / scripts/build-bsd.sh)\n'
    server_binary="${build_dir}/src/merovingian-server"
    if [ -x "$server_binary" ] && command -v readelf >/dev/null 2>&1; then
        elf_report=$(sh "$(dirname "$0")/check-elf-hardening.sh" "$server_binary" 2>&1) && elf_status=ok || elf_status=fail
        printf -- '- ELF hardening check (`scripts/check-elf-hardening.sh`) against `merovingian-server`: **%s**\n\n' "$elf_status"
        printf '```\n%s\n```\n\n' "$elf_report"
    else
        printf -- '- ELF hardening check skipped: readelf unavailable or binary not found on this platform\n\n'
    fi

    printf '**Pinned dependency versions** (`subprojects/*.wrap`)\n\n'
    printf '| Dependency | Version (source_filename) |\n'
    printf '|---|---|\n'
    for wrap in "$(dirname "$0")"/../subprojects/*.wrap; do
        name=$(basename "$wrap" .wrap)
        version=$(awk -F'= *' '/^source_filename/ {print $2; exit}' "$wrap")
        printf '| %s | %s |\n' "$name" "${version:-unpinned}"
    done
    printf '\n'

    printf '**Test log summary**\n\n'
    testlog="${build_dir}/meson-logs/testlog.txt"
    if [ -f "$testlog" ]; then
        summary=$(grep -E '^(Ok|Fail|Timeout|Expected Fail):' "$testlog" | tail -n 8)
        if [ -n "$summary" ]; then
            printf '```\n%s\n```\n\n' "$summary"
        else
            printf -- '- test log present but no Ok/Fail/Timeout summary line found (see build logs)\n\n'
        fi
    else
        printf -- '- no test log at %s (this platform job may not run the full suite)\n\n' "$testlog"
    fi

    printf '**Fuzz targets covered by the mandatory fuzz gate** (`.github/workflows/fuzz.yml`, runs on every push/PR)\n\n'
    fuzz_script="$(dirname "$0")/run-fuzz-targets.sh"
    if [ -f "$fuzz_script" ]; then
        grep -oE 'run_target [a-z0-9-]+' "$fuzz_script" | awk '{print "- `" $2 "`"}'
    else
        printf -- '- fuzz target list unavailable (scripts/run-fuzz-targets.sh not found)\n'
    fi
    printf '\n'

    printf '**Sanitizer coverage**\n\n'
    printf -- '- This release build does not itself run under a sanitizer (release/hardened profile). ASan+UBSan and TSan coverage of this same source tree run separately on every push/PR via `.github/workflows/sanitizers.yml`; see that workflow run for the corresponding commit for sanitizer logs.\n\n'
} >> "$output_file"

printf 'collect-release-evidence: wrote %s section to %s\n' "$platform_label" "$output_file"
