#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# pkgsrc RCD_SCRIPTS target — installed to ${PREFIX}/share/examples/rc.d/merovingian

# PROVIDE: merovingian
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="merovingian"
rcvar="${name}"
command="@PREFIX@/bin/merovingian-server"
command_args="--config ${merovingian_config:-@PKG_SYSCONFDIR@/merovingian/merovingian.conf}"
merovingian_user="${merovingian_user:-merovingian}"
pidfile="/var/run/merovingian/merovingian.pid"

start_precmd="merovingian_precmd"

merovingian_precmd() {
    install -d -o "${merovingian_user}" -g "${merovingian_user}" -m 0750 /var/run/merovingian
    install -d -o "${merovingian_user}" -g "${merovingian_user}" -m 0750 /var/db/merovingian
    install -d -o "${merovingian_user}" -g "${merovingian_user}" -m 0750 /var/log/merovingian
}

load_rc_config "${name}"
: "${merovingian=NO}"
run_rc_command "$1"
