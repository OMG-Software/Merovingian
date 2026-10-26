# Open registration needs an explicit acknowledgement, and still uses UIA

* Status: accepted
* Date: 2026-10-26

## Context and Problem Statement

Config validation refused `security.registration.enabled=true` with
`require_token=false` outright. Complement creates its users through
`POST /_matrix/client/v3/register` with `m.login.dummy` and cannot supply a
registration token, so it could not run against the server at all.

The handler also had a dormant spec defect: with `require_token=false` it
skipped User-Interactive Authentication (UIA) entirely and registered a request
with no `auth` data. The spec says "a request to an endpoint that uses
User-Interactive Authentication never succeeds without auth. Homeservers may
allow requests that don't require auth by offering a stage with only the
`m.login.dummy` auth type, but they must still give a 401 response to requests
with no auth data." Validation made that path unreachable, so it had never
shipped.

## Decision Drivers

* Open registration is an abuse risk on a public server. It must never be the
  result of a typo or a half-edited config.
* Complement must run against the shipped binary (ADR-0230).
* The spec, not a convenient shortcut, decides the UIA behaviour.

## Considered Options

* An acknowledgement key, `security.registration.allow_open_registration`,
  without which `require_token=false` stays a startup error.
* Allowing `require_token=false` on its own.
* Keeping open registration impossible, and leaving Complement to an admin API.

## Decision Outcome

Chosen option: the acknowledgement key, the pattern this project already uses
for deliberate weakenings (`federation.worker.allow_without_landlock`,
`federation.worker.allow_shared_database_credentials`).

* `enabled=true`, `require_token=false` is valid only with
  `allow_open_registration=true`.
* Open registration answers a request with no `auth` with 401 and a single
  flow with the single stage `m.login.dummy`, plus a session. It completes on
  `m.login.dummy`, with or without that session. Any other stage, or a session
  this server did not issue for `register`, gets the challenge again.
* The open state is logged at CRITICAL on every start.

### Positive Consequences

* Complement can create users through the normal registration endpoint.
* `/register` keeps to the UIA contract in both modes.

### Negative Consequences

* One more key that an operator can use to weaken a public server. The
  CRITICAL log line and the explicit name are the mitigations.

## Pros and Cons of the Options

### Allowing `require_token=false` on its own

* Good, because it is one key fewer.
* Bad, because a single flipped boolean opens public registration.

### Keeping open registration impossible

* Good, because the abuse risk stays at zero.
* Bad, because Complement has no other way to create ordinary users: its
  shared-secret admin endpoint is Synapse's, and tests that need it are skipped
  when it answers 404.

## Links

* [ADR-0230](0230-federation-may-reach-operator-named-private-networks-and-nothing-else.md)
* `docs/matrix-v1.19-spec/client-server-api.md`, "User-Interactive Authentication API"
