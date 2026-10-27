# SPDX-FileCopyrightText: 2026 James Chapman
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Sourced by the Complement image's scripts. SERVER_NAME comes from whoever
# starts the container and is written into the config and the certificate, so
# it is checked against the spec's server-name grammar (appendices.md, "Server
# Name") before any script uses it, and refused, never cleaned:
#
#   server_name = hostname [ ":" port ]
#   hostname    = IPv4address / "[" IPv6address "]" / dns-name
#   dns-name    = 1*255dns-char   (DIGIT / ALPHA / "-" / ".")
#
# The server applies its own, stricter checks to server.name at start-up.

# Succeeds when $1 is a server name. A value containing a line break is
# refused first: grep matches line by line, so "hs1<LF>evil" would otherwise
# pass on its first line.
complement_server_name_is_valid() {
    csn_name=$1
    case $csn_name in
        '' | *'
'*)
            return 1
            ;;
    esac
    printf '%s\n' "$csn_name" | grep -Eqx '(\[[0-9A-Fa-f:.]{2,45}\]|[A-Za-z0-9.-]{1,255})(:[0-9]{1,5})?' || return 1
    case $csn_name in
        \[*\]) return 0 ;;
        \[*\]:*) csn_port=${csn_name##*\]:} ;;
        *:*) csn_port=${csn_name#*:} ;;
        *) return 0 ;;
    esac
    [ "$csn_port" -ge 1 ] && [ "$csn_port" -le 65535 ]
}

# Prints the hostname part of a server name already checked above: the name
# without its port, an IPv6 literal without its brackets.
complement_server_name_host() {
    csn_name=$1
    case $csn_name in
        \[*)
            csn_name=${csn_name#\[}
            printf '%s\n' "${csn_name%%\]*}"
            ;;
        *)
            printf '%s\n' "${csn_name%%:*}"
            ;;
    esac
}

# Exits with status 2 unless $1 is a server name.
complement_require_server_name() {
    if ! complement_server_name_is_valid "$1"; then
        echo "complement: SERVER_NAME is not a Matrix server name" >&2
        exit 2
    fi
}
