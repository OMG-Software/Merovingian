# The federation worker loads no application service registrations

* Status: accepted
* Date: 2026-10-30

## Context and Problem Statement

`start_runtime` parses `appservice.registration_files` and creates each
registration's sender user. The federation worker calls `start_runtime` too, so
it tried to open the same files. A registration holds the `as_token` and
`hs_token`, which are secrets, and a Complement image keeps them in
`/var/lib/merovingian/secrets`, outside the worker's Landlock grants
(ADR-0062 part 3, `tests/complement/AGENTS.md` rule 6). Every start logged
`start.appservice_registration_rejected ... cannot open appservice registration
file` from the worker and `appservices_ready count=0`.

Does the worker need the registrations, or should the files be made readable to it?

## Considered Options

* The worker does not load registrations (`RuntimeStartOptions::load_appservices`
  false).
* Grant the worker read access to the registration directory (or put the
  registrations in a directory it is granted).
* Leave the rejection as a logged warning.

## Decision Outcome

Chosen option: the worker does not load registrations. Everything that uses
`runtime.appservices` (token authentication and masquerade, namespace and
exclusivity checks, the delivery queue, the ephemeral queue, the sender-user
creation) runs in main. The worker relays every state-changing federation
request to main, never queues a delivery, and its database role is
least-privilege (ADR-0062), so creating a sender user from there would be a
write it must not make, and an `as_token` in its memory is a secret it has no
use for.

The Complement image needed no change: registrations stay in
`secrets/appservice`, readable by main only through its own grants.

### Negative Consequences

* A future worker handler that consults `runtime.appservices` would see an empty
  registry and silently decide as if no appservice existed. Such a decision
  belongs in main (relay it) and not in the worker; do not re-enable loading
  to make it work.

## Links

* ADR-0062 (the worker holds no secret files), ADR-0078 (the worker never signs)
* `src/federation_worker/AGENTS.md`
