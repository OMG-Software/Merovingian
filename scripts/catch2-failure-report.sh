#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# catch2-failure-report.sh [--exclude ERE] TESTLOG
#
# Prints, from a Meson testlog.txt, the output of every test that did not pass,
# with the homeserver's runtime log lines removed, so what remains is each
# failed Catch2 case: its scenario header, file and line, FAILED:, the
# expansion and any exception message, then the run's totals. CI runs it when a
# build-and-test step fails (ADR-0877).
#
# A tail of the whole log is not enough: Meson writes tests in the order they
# finish, so the smoke tests that run after an early integration shard push its
# failure out of any fixed number of trailing lines.
#
# Meson starts each test with a "==== N/M ====" banner and ends it with a line
# of exactly 78 "=" (78 "-" in older Meson; Catch2's own rules are 79 wide, so
# neither is mistaken for the other). A test failed unless its
# "result:" is "exit status 0", or "exit status 77", which Meson reads as a
# skip. Each failed test prints at most the first HEAD_LINES of its filtered
# output and its last TAIL_LINES, and the whole report at most TOTAL_LINES: a
# test that does not fit is cut further, or counted as not shown. Lines left out
# can hold an assertion, so the report says how many and where the full log is.
# --exclude drops more lines (an extended regular expression), as the NetBSD
# job does for its [netbsd-diag] markers. POSIX sh and awk only, with no
# interval expressions, so it runs as is on the BSD VMs and in every container.

set -eu

exclude=''
while [ $# -gt 0 ]; do
    case "$1" in
        --exclude)
            [ $# -ge 2 ] || { echo "catch2-failure-report.sh: --exclude needs a pattern" >&2; exit 2; }
            exclude=$2
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            echo "catch2-failure-report.sh: unknown option $1" >&2
            exit 2
            ;;
        *)
            break
            ;;
    esac
done
if [ $# -ne 1 ]; then
    echo "usage: catch2-failure-report.sh [--exclude ERE] TESTLOG" >&2
    exit 2
fi
testlog=$1

head_lines=${CATCH2_REPORT_HEAD_LINES:-400}
tail_lines=${CATCH2_REPORT_TAIL_LINES:-100}
total_lines=${CATCH2_REPORT_TOTAL_LINES:-4000}
for cap in "$head_lines" "$tail_lines" "$total_lines"; do
    case "$cap" in
        '' | *[!0-9]*)
            echo "catch2-failure-report.sh: a line cap must be a whole number, not '$cap'" >&2
            exit 2
            ;;
    esac
done
# The smallest total that holds the closing summary (3 lines) and one test cut to
# its fewest lines (10, its 4 markers and the omission note), so no cap is broken.
if [ "$total_lines" -lt 20 ]; then
    echo "catch2-failure-report.sh: CATCH2_REPORT_TOTAL_LINES must be at least 20, not $total_lines" >&2
    exit 2
fi

if [ ! -f "$testlog" ]; then
    printf 'No test log at %s: meson test did not run, so read the failed step above.\n' "$testlog"
    exit 0
fi

REPORT_TESTLOG=$testlog \
EXCLUDE_ERE=$exclude \
HEAD_LINES=$head_lines \
TAIL_LINES=$tail_lines \
TOTAL_LINES=$total_lines \
    awk '
function is_rule(line, ch) {
    if (length(line) != 78) return 0
    return (ch == "=" && line ~ /^=+$/) || (ch == "-" && line ~ /^-+$/)
}
function is_runtime_log(line) {
    # 2026-11-24 10:00:00.123456 +0000  <LEVEL>  module: message
    return line ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]+ \+[0-9][0-9][0-9][0-9]  <(INFO|WARNING|ERROR|DEBUG|CRITICAL)>/
}
function out(line) {
    print line
    printed++
}
function finish_test(    i, first_tail, per_test, room, body, head, tail) {
    if (!inside) return
    inside = 0
    if (result == "exit status 0" || result == "exit status 77") return
    failed++
    # The lines left for the output of this test once its own markers (a blank line, FAILED, the command and the
    # end line) and the closing summary are counted, so the report never passes TOTAL_LINES.
    room = total_cap - SUMMARY_LINES - printed - 3 - (command != "" ? 1 : 0)
    per_test = head_cap + tail_cap
    if (n <= per_test && n <= room) {
        head = n
        tail = 0
    } else {
        # Cut: one line goes to the note that counts what was left out.
        body = per_test < room - 1 ? per_test : room - 1
        if (body < MIN_CUT_LINES && body < per_test) {
            unshown++
            return
        }
        head = per_test > 0 ? int(body * head_cap / per_test) : 0
        tail = body - head
    }
    out("")
    out("########## FAILED " name "  (" result ", " duration ")")
    if (command != "") out("command: " command)
    for (i = 1; i <= head; i++) out(buf[i])
    if (head + tail < n) {
        first_tail = n - tail + 1
        out("[... " (first_tail - head - 1) " lines omitted; the full output is in " testlog " ...]")
        for (i = first_tail; i <= n; i++) out(buf[i])
    }
    out("########## end of " name)
}
BEGIN {
    # Read from the environment, not -v, which would process backslash escapes.
    testlog = ENVIRON["REPORT_TESTLOG"]
    exclude = ENVIRON["EXCLUDE_ERE"]
    head_cap = ENVIRON["HEAD_LINES"] + 0
    tail_cap = ENVIRON["TAIL_LINES"] + 0
    total_cap = ENVIRON["TOTAL_LINES"] + 0
    inside = 0; failed = 0; printed = 0; unshown = 0
    # The closing summary: a blank line, the count, and the not-shown count.
    SUMMARY_LINES = 3
    # A test cut to fewer lines than this by the total cap is counted as not shown instead.
    MIN_CUT_LINES = 10
}
{ sub(/\r$/, "") }
length($0) == 78 && /^=+ [0-9]+\/[0-9]+ =+$/ {
    finish_test()
    inside = 1; n = 0; name = "(unnamed test)"; result = ""; duration = ""; command = ""
    in_header = 1
    next
}
!inside { next }
is_rule($0, "=") || is_rule($0, "-") {
    finish_test()
    next
}
in_header && /^test:         / { name = substr($0, 15); next }
in_header && /^result:       / { result = substr($0, 15); next }
in_header && /^duration:     / { duration = substr($0, 15); next }
in_header && /^command:      / { command = substr($0, 15); next }
in_header && /^start time:   / { next }
/^-+ (stdout|output|stderr) -+$/ { in_header = 0; buf[++n] = $0; next }
is_runtime_log($0) { next }
exclude != "" && $0 ~ exclude { next }
{ buf[++n] = $0 }
END {
    finish_test()
    if (failed == 0) {
        print "No failed test in " testlog "; Meson failed before or outside a test (read the step above)."
    } else {
        print ""
        print failed " failed test(s) in " testlog "."
        if (unshown > 0) print unshown " of them not shown: the report reached " total_cap " lines."
    }
}
' "$testlog"
