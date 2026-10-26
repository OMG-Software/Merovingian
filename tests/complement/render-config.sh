#!/bin/sh
# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Usage: render-config.sh TEMPLATE SERVER_NAME ALLOW_WITHOUT_LANDLOCK
#
# Prints TEMPLATE with its placeholders filled. Every value is checked before
# anything is printed, so a refused value leaves no partial config behind:
#
#   @SERVER_NAME@             SERVER_NAME, a Matrix server name
#   @ALLOW_WITHOUT_LANDLOCK@  exactly "true" or "false"
#   @ROOT@                    $MEROVINGIAN_COMPLEMENT_ROOT, empty in the image;
#                             tests set it to render paths under a scratch
#                             directory instead of /

set -eu

here=$(dirname "$0")
. "$here/server-name.sh"

if [ "$#" -ne 3 ]; then
    echo "usage: render-config.sh TEMPLATE SERVER_NAME ALLOW_WITHOUT_LANDLOCK" >&2
    exit 2
fi
template=$1
server_name=$2
allow_without_landlock=$3
root=${MEROVINGIAN_COMPLEMENT_ROOT:-}

complement_require_server_name "$server_name"

case $allow_without_landlock in
    true | false) ;;
    *)
        echo "complement: the Landlock waiver must be exactly true or false" >&2
        exit 2
        ;;
esac

# The root is substituted into paths and into sed's replacement text, so it is
# limited to absolute paths of plain characters (no '|', '&', '\' or spaces).
case $root in
    *'
'*)
        echo "complement: MEROVINGIAN_COMPLEMENT_ROOT is not a plain absolute path" >&2
        exit 2
        ;;
esac
if [ -n "$root" ] && ! printf '%s\n' "$root" | grep -Eqx '(/[A-Za-z0-9._-]+)+'; then
    echo "complement: MEROVINGIAN_COMPLEMENT_ROOT is not a plain absolute path" >&2
    exit 2
fi

# A server name holds only [A-Za-z0-9.:-] and brackets, none of which is
# special in a sed replacement or the '|' delimiter.
rendered=$(sed \
    -e "s|@SERVER_NAME@|${server_name}|g" \
    -e "s|@ALLOW_WITHOUT_LANDLOCK@|${allow_without_landlock}|g" \
    -e "s|@ROOT@|${root}|g" \
    "$template")

if printf '%s\n' "$rendered" | grep -Eq '@[A-Z_]+@'; then
    echo "complement: the template has a placeholder this script does not fill" >&2
    exit 2
fi

printf '%s\n' "$rendered"
