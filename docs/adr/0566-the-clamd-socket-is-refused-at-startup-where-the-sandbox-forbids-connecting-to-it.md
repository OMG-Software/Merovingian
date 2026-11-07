# The clamd socket is refused at startup where the sandbox forbids connecting to it

* Status: accepted
* Deciders: repository owner
* Date: 2026-11-07

## Context and Problem Statement

The main process runs inside a platform sandbox. Can it connect to a clamd AF_UNIX socket, and what happens on a platform where it cannot?

## Decision Outcome

Checked per platform (ADR-0565):

* Linux: the seccomp allow-list permits `socket` for AF_UNIX, `connect`, `poll`, `send` and `recv`; Landlock confines only the federation worker. Supported.
* NetBSD: no in-process sandbox is applied to the main process. Supported.
* FreeBSD: the main process enters Capsicum capability mode, which forbids connecting to a socket by path. Not supported.
* OpenBSD: `pledge` includes `unix`, but `unveil` hides every path not listed, and the socket path is operator-chosen and not listed. Not supported.

`media::clamd_supported_on_this_platform()` answers this, and `main.cpp` refuses to start (a config validation error naming `security.media.clamd_socket_path`) when the key is set on an unsupported platform. The alternative, starting and quarantining every file at run time, hides the misconfiguration.

## Rejected alternatives

* Adding the configured path to the OpenBSD unveil list: plausible, but not testable here, and the unveil plan is irreversible (ADR-0162). A follow-up can add it with a real OpenBSD test.
* Pre-opening a connection before Capsicum: clamd needs one connection per scan, so a held connection does not work.
