#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Fails unless the integration suite's Meson tests, taken together, run every
# scenario of the integration binary exactly once. tests/meson.build splits that
# binary into Catch2 shards (--shard-count/--shard-index) plus filtered tests
# for the scenarios that must not share a machine with concurrent processes; a
# shard that picks another seed, a filter that leaves a scenario out, or a
# scenario carrying two of the filtered tags would otherwise lose or repeat a
# scenario without any test failing.
#
# usage: check-integration-shards.sh BINARY SHARD_COUNT SEED SHARD_FILTER [OTHER_FILTER...]
#
# BINARY is merovingian-integration-tests. Each shard is listed with
# `--order rand --rng-seed SEED --shard-count SHARD_COUNT --shard-index I`
# and SHARD_FILTER, as tests/meson.build runs it; each OTHER_FILTER is one
# Meson test's test spec. The scenario names of all of them, sorted, must equal
# the unfiltered list. Only names are listed: no scenario runs.

set -eu

if [ "$#" -lt 4 ]; then
    printf '%s\n' 'usage: check-integration-shards.sh BINARY SHARD_COUNT SEED SHARD_FILTER [OTHER_FILTER...]' >&2
    exit 2
fi

binary=$1
count=$2
seed=$3
shard_filter=$4
shift 4

case "$count" in
    '' | *[!0-9]* | 0)
        printf '%s\n' "SHARD_COUNT must be a positive whole number, got '$count'." >&2
        exit 2
        ;;
esac

if [ ! -x "$binary" ]; then
    printf '%s\n' "$binary is not an executable file." >&2
    exit 2
fi

# The skip gate's XML report would otherwise capture this listing, and its
# reader treats a report with no test run as truncated.
unset MEROVINGIAN_CATCH_REPORT_DIR || true

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# list OUTPUT ARGS...: the scenario names the binary would select, one per line.
list() {
    output=$1
    shift
    # Catch2 3 prints one name per line for --list-tests at quiet verbosity; it
    # has no --list-test-names-only, which Catch2 2 had.
    if ! "$binary" --list-tests --verbosity quiet "$@" >"$work/raw" 2>"$work/error"; then
        printf '%s\n' "$binary --list-tests --verbosity quiet $* failed:" >&2
        cat "$work/error" >&2
        exit 2
    fi
    sed '/^[[:space:]]*$/d' "$work/raw" >"$output"
}

list "$work/full" --order rand --rng-seed "$seed"
if [ ! -s "$work/full" ]; then
    printf '%s\n' 'The integration binary lists no scenarios; refusing to pass an empty check.' >&2
    exit 2
fi

: >"$work/selected"
index=0
while [ "$index" -lt "$count" ]; do
    list "$work/shard.$index" "$shard_filter" --order rand --rng-seed "$seed" \
        --shard-count "$count" --shard-index "$index"
    if [ ! -s "$work/shard.$index" ]; then
        printf '%s\n' "Shard $index of $count selects no scenario." >&2
        exit 1
    fi
    cat "$work/shard.$index" >>"$work/selected"
    index=$((index + 1))
done

other=0
for filter in "$@"; do
    list "$work/other.$other" "$filter"
    if [ ! -s "$work/other.$other" ]; then
        printf '%s\n' "The filter '$filter' selects no scenario." >&2
        exit 1
    fi
    cat "$work/other.$other" >>"$work/selected"
    other=$((other + 1))
done

LC_ALL=C sort "$work/full" >"$work/want"
LC_ALL=C sort "$work/selected" >"$work/got"
if ! cmp -s "$work/want" "$work/got"; then
    printf '%s\n' 'The integration Meson tests do not run every scenario exactly once.' >&2
    printf '%s\n' '< only in the full list (never run)   > only in the Meson tests (run more than once or not in the binary)' >&2
    diff "$work/want" "$work/got" | head -n 40 >&2 || true
    exit 1
fi

printf '%s\n' "$(wc -l <"$work/want" | tr -d ' ') scenarios, each in exactly one of $count shards and $# filtered tests."
