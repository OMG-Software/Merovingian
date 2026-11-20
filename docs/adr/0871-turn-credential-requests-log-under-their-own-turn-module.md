# TURN credential requests log under their own `turn` module, and never log a credential

* Status: accepted
* Date: 2026-11-20

## Context and Problem Statement

`GET /_matrix/client/v3/voip/turnServer` is handled inline in `ClientServerRuntime.cpp`, whose file-local
`log_diagnostic` wrapper files every line under the `client_server` module. Its one diagnostic,
`turn.credentials_unavailable`, could therefore be raised or silenced only together with every other client-server
line, and an issued credential was not logged at all. An operator debugging calls ("why does this client get no
relay?") had nothing to filter on. LiveKit already has its own `livekit` module (`log_modules.livekit`).

## Decision Drivers

* An operator must be able to turn TURN logging up or down without touching `client_server`.
* The answer holds a working credential: the username (`<expiry>:<user_id>` with a shared secret, or the static one)
  and the password. Neither may reach a log, and the shared secret never leaves the request's `SecretBuffer`
  (ADR-0480).

## Considered Options

* Keep the lines under `client_server` and add an issued line there.
* Log the route under a `turn` module through its own wrapper, `log_turn_diagnostic`.
* Move the whole route out of `ClientServerRuntime.cpp` into a TURN service file with its own module constant.

## Decision Outcome

Chosen option: "a `turn` module through `log_turn_diagnostic`". The route logs `turn.credentials_issued` (info),
`turn.credentials_unavailable` (error) and `turn.not_configured` (debug), each with `user_id`; the issued line adds
`credential` (`static` or `shared_secret`), `ttl_seconds` and `uri_count`, and the unavailable line a fixed `reason`.
No field carries credential text: the username, the password and the shared secret are never fields of any line. Moving the route out of `ClientServerRuntime.cpp` was not needed to get a module
of its own and would have moved forty lines of unrelated JSON building with it.

### Positive Consequences

* `log_modules.turn` sets the level of every line the TURN handler writes; `log_modules.turn=warning` hides the
  per-request info line. Only requests that reach the handler are logged there: a missing, expired or unknown access
  token is refused with 401 before it, and logged as `request.auth.rejected` (debug) under `client_server`, so look
  there for authentication failures. `turn.not_configured` is a debug line, which reaches the console only when the
  server also runs with `--debug`.
* The logging tests run with `client_server` silenced, so a line moved back under `client_server` fails them.

### Negative Consequences

* An issued credential is one info line per successful request at the default level. The ttl does not bound that:
  a client may ask again before its credential expires (for example at the start of each call), and every request
  writes a line. An operator who finds it loud sets `log_modules.turn=warning`.
* Changing the module of `turn.credentials_unavailable` means a filter on `client_server` no longer sees it.

## Rules for future code

* A new diagnostic of `GET /voip/turnServer` goes through `log_turn_diagnostic`, never the `client_server` wrapper.
* Never add the username or the password as a field, even at debug or trace level. The password is the secret that
  matters. The username is withheld for two reasons that hold whatever else the line carries:
  * With static credentials (`server.turn.username`) it is a configured value that nothing else in a log reveals, the
    same for every user, and one of the two halves of a credential every user of the server may relay with.
  * One rule for both kinds keeps every line free of credential text, so a log can be pasted into an issue or a
    support thread without first working out which parts of it are safe.
* With a shared secret, withholding the username hides little: it is `<expiry>:<user_id>`, and the expiry can be
  rebuilt to the second from the line's timestamp and `ttl_seconds`. That is accepted, because the username without the
  password, which needs the shared secret, grants nothing. Do not read it as a reason to start logging the username:
  the static case still forbids it.

## Links

* Refines [ADR-0480](0480-turn-credentials-come-from-a-coturn-shared-secret-file-through-an-openssl-hmac-sha1.md)
