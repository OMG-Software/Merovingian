# The server exits when its federation worker cannot start

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: refines [ADR-0041](0041-refuse-to-start-the-federation-worker-unsandboxed.md),
which says federation degrades to 503 when the worker refuses to start.

## Context and Problem Statement

The first FreeBSD run of the startup hardening gate showed the server exiting with
status 80 when the worker refused to run unsandboxed. ADR-0041 and `docs/hardening.md`
said federation would degrade to 503 instead. With federation on, `main.cpp` treats a
failed first spawn as fatal, and has done since the worker became mandatory. So a FreeBSD
server on the default config does not start at all. Was the record wrong, or the code?

## Considered Options

* Keep exiting at startup, and correct the record
* Restore the 503: keep serving clients with federation down

## Decision Outcome

Chosen option: keep exiting at startup. A failure at startup means the configuration can
never work, and an operator should learn that at once, from a service that will not start.
A server that looks healthy while federation answers 503 is easy to overlook, and the 503
would need a new startup path that exists only for a misconfiguration.

ADR-0041's rule stands: the server never accepts federation traffic through an unsandboxed
worker. Its statement of how that failure appears does not.

### Consequences

* An operator on a platform with no worker sandbox must choose before the server will start:
  `federation.worker.apply_hardening=false`, or `security.federation.enabled=false` for a
  non-federating server.
* This covers the first spawn only. A worker that dies after startup is still restarted with
  backoff, and federation requests answer 503 while it is down, so one crash does not take
  local users down with it.
