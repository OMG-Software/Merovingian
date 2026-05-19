#!/bin/sh
# Wrapper for OpenSSL's Configure script that strips --bindir from arguments.
# OpenSSL's Configure does not support --bindir (an autotools convention) and
# incorrectly adds it to CFLAGS, causing clang to fail with "unknown argument".
# Meson's external_project module auto-adds --bindir=@PREFIX@/@BINDIR@ when
# @BINDIR@ is not present in configure_options, so we strip it here.

filtered_args=""
skip_next=""
for arg in "$@"; do
    if [ -n "$skip_next" ]; then
        skip_next=""
        continue
    fi
    case "$arg" in
        --bindir=*)
            # Strip --bindir=VALUE
            ;;
        --bindir)
            # Strip --bindir VALUE (space-separated)
            skip_next="yes"
            ;;
        *)
            filtered_args="$filtered_args $arg"
            ;;
    esac
done

exec "$(dirname "$0")/Configure" $filtered_args
