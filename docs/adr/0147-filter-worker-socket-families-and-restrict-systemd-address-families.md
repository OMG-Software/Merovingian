# Filter the worker's socket families, and restrict them in the systemd unit

* Status: accepted
* Date: 2026-10-15

Technical Story: ISO-8 in the 29 September 2026 security audit.

## Context and Problem Statement

The federation worker's seccomp profile allowed `socket()` and `socketpair()` for every
address family, so a compromised worker could reach kernel attack surface it has no use
for (`AF_ALG`, `AF_PACKET`, `AF_VSOCK` and the rest). The systemd unit set no
`RestrictAddressFamilies=` and none of the kernel-protection directives.

The worker needs `AF_INET`/`AF_INET6` for federation and DNS and `AF_UNIX` for its IPC
channel and a local PostgreSQL socket. glibc's `getaddrinfo` also opens a routing
`AF_NETLINK` socket when a name resolves to more than one address, to sort them
(RFC 3484), and falls back when that socket cannot be created.

## Considered Options

* Allow exactly `AF_UNIX`, `AF_INET`, `AF_INET6`; kill on everything else, `AF_NETLINK`
  included.
* Also allow `AF_NETLINK` (or `NETLINK_ROUTE` only).
* Allow the three families, answer `AF_NETLINK` with `EAFNOSUPPORT`, kill on the rest.

## Decision Outcome

Chosen option: the third. `socket()` admits `AF_UNIX`, `AF_INET` and `AF_INET6`;
`AF_NETLINK` returns `EAFNOSUPPORT`; any other domain kills the worker. `socketpair()`
admits `AF_UNIX` only. The systemd unit sets
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, which also answers other families
with `EAFNOSUPPORT`, plus `RestrictNamespaces=`, `ProtectKernelTunables=`,
`ProtectKernelModules=`, `ProtectKernelLogs=`, `ProtectControlGroups=`,
`ProtectClock=` and `ProtectHostname=`.

Killing on `AF_NETLINK` is rejected because a federation peer whose name has both an
IPv4 and an IPv6 address would crash the worker in `getaddrinfo`; no test with a
single loopback address would show it. Allowing netlink is rejected because nothing
needs it once glibc's fallback works. The main process's own filter is unchanged:
systemd's directive covers it, and its sockets come from more libraries (libcurl,
libpq) than the worker's.

### Positive Consequences

* `socket(AF_ALG, …)` and every other unused family is fatal to a compromised worker.
* The unit's restriction matches the worker filter, so the two cannot disagree on
  what glibc sees.

### Negative Consequences

* Landlock does not govern `connect()` on a pathname `AF_UNIX` socket, so the worker
  can still reach any local socket its uid may open. The worker's PostgreSQL role
  should authenticate with a password (or certificate), not `peer`, so that reaching
  the socket is not enough.
* Address sorting for multi-address names falls back to glibc's default order.

## Links

* Refines [ADR-0112](0112-restrict-worker-signals-and-resource-limits.md) — the
  argument-checked block pattern used here.
