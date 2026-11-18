# SRV lookups on glibc own their resolver state and serialise its setup

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

Technical Story: the `tsan` job's data-race report in `SystemServerDiscoveryNetwork::lookup_srv` on `main`, surfaced by
PR #600.

## Context and Problem Statement

ADR-0355 kept `res_query` on glibc, whose `_res` is per thread. ThreadSanitizer then reported two threads' lookups in
`tests/unit/test_server_discovery_system_resolver.cpp` racing in `realloc`, from glibc's
`__libc_dynarray_emplace_enlarge`. A thread's first lookup initialises its resolver state, and glibc attaches every
thread's state to one process-wide array of configurations (`__resolv_conf_attach` in `resolv/resolv_conf.c`), which
grows it. glibc guards that array with an internal lock. ThreadSanitizer cannot see that lock, because libc is not
instrumented and the lock is not a `pthread_mutex`, so it saw two unordered writes. TSan's own `getaddrinfo` interceptor
ignores accesses inside the call for the same reason. The report is a false positive, but `tsan` is a required check
and `tests/sanitizer/tsan.supp` may not suppress a report whose stack runs through our code. What should `lookup_srv` do
on glibc?

## Considered Options

* A state owned by each lookup (`res_ninit`, `res_nquery`, `res_nclose`), with `res_ninit` and `res_nclose` under one
  process-wide mutex
* One mutex around `res_query`
* A suppression for `__libc_dynarray_emplace_enlarge`

## Decision Outcome

Chosen option: a state owned by each lookup, with its setup and teardown serialised. On glibc `ResolverState` (the
NetBSD type of ADR-0355, built for glibc too) calls `res_ninit` and `res_nclose` under `resolver_configuration_mutex`.
Those are the two steps that change the shared array, and neither reaches the network: `res_ninit` reads
`resolv.conf`, which glibc caches by file status. `res_nquery`, which waits on name servers, runs outside the mutex,
so lookups stay parallel. TSan sees the mutex and orders the two steps. musl and the BSDs other than NetBSD keep
`res_query`.

### Positive Consequences

* The `tsan` job passes without a suppression in our code's stack.
* A slow name server still delays only the lookup waiting for it (ADR-0355).

### Negative Consequences

* Each glibc lookup sets up and tears down its own state, a local step beside a network round trip.
* Lookups' setups wait for one another for that local step.
* `getaddrinfo` attaches its thread's state through the same array with no mutex of ours. TSan ignores accesses inside
  its interceptor, so this does not report, but the setup is serialised only among SRV lookups.

## Pros and Cons of the Options

### One mutex around `res_query`

The smallest change, and it orders everything TSan sees. ADR-0355 rejected it: the mutex would be held through the
resolver's retries against a name server a remote operator chooses, so one unresponsive one would stall every other
destination's discovery.

### A suppression for `__libc_dynarray_emplace_enlarge`

It would hide this report only, and the frame belongs to glibc. The report's stack still runs through `lookup_srv`, and
`tsan.supp`'s rule forbids that, because a `race:` entry matches any frame. A wrong suppression would hide a real race
in our code on the same path.
