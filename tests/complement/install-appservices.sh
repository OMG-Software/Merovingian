#!/bin/sh
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Usage: install-appservices.sh SOURCE_DIR DEST_DIR GROUP
#
# Complement copies each application service registration a test needs into
# SOURCE_DIR (its MountAppServicePath, /complement/appservice/<id>.yaml) before
# it starts the container. This copies them into DEST_DIR, which only its owner
# (root, in the image) can write, readable by GROUP, and prints their paths as
# the comma-separated value of appservice.registration_files: nothing when
# there are none.
#
# Every entry is checked before anything is written (tests/complement/AGENTS.md,
# "Check, then write"): only regular files with a plain name ending in .yaml,
# each at most 64 KiB. Anything else is refused, never skipped. Every start is a
# restart, so DEST_DIR is emptied first and holds only the current set.

set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: install-appservices.sh SOURCE_DIR DEST_DIR GROUP" >&2
    exit 2
fi
source_dir=$1
dest_dir=$2
group=$3
max_bytes=65536

refuse() {
    echo "complement: application service registrations: $1" >&2
    exit 2
}

if [ -L "$dest_dir" ]; then
    refuse "$dest_dir is a link"
fi
if [ -e "$dest_dir" ] && [ ! -d "$dest_dir" ]; then
    refuse "$dest_dir is not a directory"
fi

names=""
if [ -L "$source_dir" ]; then
    refuse "$source_dir is a link"
fi
if [ -e "$source_dir" ]; then
    if [ ! -d "$source_dir" ]; then
        refuse "$source_dir is not a directory"
    fi
    for entry in "$source_dir"/* "$source_dir"/.[!.]*; do
        if [ ! -e "$entry" ] && [ ! -L "$entry" ]; then
            continue
        fi
        name=${entry##*/}
        # The list is comma-separated, so a comma (or anything unusual) in a
        # name is refused rather than escaped.
        if ! printf '%s\n' "$name" | grep -Eqx '[A-Za-z0-9._%-]+\.yaml'; then
            refuse "unexpected entry $name"
        fi
        if [ -L "$entry" ] || [ ! -f "$entry" ]; then
            refuse "$name is not a regular file"
        fi
        if [ "$(wc -c <"$entry")" -gt "$max_bytes" ]; then
            refuse "$name is larger than $max_bytes bytes"
        fi
        names="$names $name"
    done
fi

if [ -z "$names" ] && [ ! -e "$dest_dir" ]; then
    exit 0
fi

install -d -m 0755 "$dest_dir"
# Copies from an earlier start are removed, never written through.
find "$dest_dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +

list=""
for name in $names; do
    install -m 0640 -g "$group" "$source_dir/$name" "$dest_dir/$name"
    list="${list:+$list,}$dest_dir/$name"
done
printf '%s\n' "$list"
