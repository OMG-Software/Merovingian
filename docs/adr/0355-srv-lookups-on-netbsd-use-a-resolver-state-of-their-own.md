# SRV lookups on NetBSD use a resolver state of their own

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: the NetBSD conformance timeout on PR #554.

## Context and Problem Statement

`SystemServerDiscoveryNetwork::lookup_srv` called `res_query`, and delivery threads discover different
destinations at the same time (ADR-0354). On NetBSD the `conformance-tests` suite timed out, and the `omit_members`
scenario alone hung within five runs.

The kernel showed why. A hung process had one thread in state `D` on `fdclose`, one in `I` on `netio`, and the main
thread in `lwpwait`, joining them. `res_query` in NetBSD's libc runs on the single process-wide `_nres`, with no lock
(`lib/libc/resolv/res_data.c`). Two threads therefore share one resolver socket: one finishes and closes it while the
other is blocked reading it. `close` waits for the reader and the reader waits for a datagram, so neither returns, and
neither a request to stop nor `SIGQUIT` ends them. Only `SIGKILL` does. The same could happen to a production
delivery thread, and shutdown would then wait on it.

`getaddrinfo` is not affected: it takes a state from a pool (`__res_get_state`, `lib/libpthread/res_state.c`). What
should `lookup_srv` do?

## Considered Options

* `res_nquery` on a state owned by the call, on NetBSD only
* One lock around `res_query`
* `res_nquery` on every platform
* Fewer delivery threads, or a longer test timeout

## Decision Outcome

Chosen option: `res_nquery` on a state owned by the call, on NetBSD only. `ResolverState` holds a `__res_state` for one
lookup, with `res_ninit` in its constructor and `res_ndestroy` in its destructor.

The other platforms keep `res_query`, which is safe there. FreeBSD's `_res` is per thread
(`lib/libc/resolv/res_state.c`) and OpenBSD's resolver context is thread-private (`lib/libc/asr/asr.c`), both read in
source for this decision. glibc's `_res` is per thread and musl's `res_query` keeps no state, both from their
documentation.

### Positive Consequences

* Lookups stay parallel, and a slow name server delays only the lookup waiting for it.

### Negative Consequences

* Each lookup on NetBSD reads `resolv.conf` and opens a kqueue and a socket, and closes them. A lookup is already a
  network round trip, so this does not change its cost materially.
* A platform-specific branch that a Linux build does not compile. Only the NetBSD CI job builds it.

## Pros and Cons of the Options

### One lock around `res_query`

Smaller, with no platform branch that goes uncompiled on Linux. The lock would be held through the resolver's retries,
and a remote operator chooses the name server, so one unresponsive one would stall discovery of every other destination.

### `res_nquery` on every platform

One code path. musl has no `res_nquery`, and the static Linux build uses musl; OpenBSD's `resolv.h` has none either.

### Fewer delivery threads, or a longer test timeout

Each hides the race from the suite and leaves it in the server.

## Links

* Related: [ADR-0354](0354-federation-delivery-gives-each-destination-at-most-one-thread.md)
