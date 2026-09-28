# Refresh tokens retire on first use of their successor

* Status: accepted
* Date: 2026-09-28

Technical Story: 0.12.13 audit, remaining-work item 6 in
`docs/todos/audit-0.12.13-handover.md` (refresh-token reuse detection).

## Context and Problem Statement

`refresh_local_session` revoked the presented refresh token as soon as it
minted a new pair. The spec (client-server-api.md, `POST /refresh`) says
otherwise: "The old refresh token remains valid until the new access token or
refresh token is used, at which point the old refresh token is revoked. This
ensures that if a client fails to receive or persist the new tokens, it will
be able to repeat the refresh operation." Its OAuth section adds that the
server "MUST ensure that the client is able to retry the refresh request in
the case that the response to the request is lost", and "SHOULD consider that
the session is compromised if an old, invalidated refresh token is used, and
SHOULD revoke the session."

The handover asked for reuse detection on top of the immediate revocation.
That would have made a lost response end the session outright, compounding
the existing MUST violation instead of fixing it.

How should a refresh token be retired so that a lost response can be retried,
yet a stolen token presented after rotation is detected?

## Considered Options

* **Record the predecessor on the new pair and retire it on first use
  (chosen).**
* **Revoke immediately and treat any second presentation as reuse.** Rejected:
  violates the spec's MUST on retry after a lost response.
* **Keep the old token valid for a fixed grace period.** Rejected: not what
  the spec says; a retry after the window fails, and a thief has the window
  too.

## Decision Outcome

Chosen option: "Record the predecessor on the new pair and retire it on first
use".

* Migration 017 adds `refresh_tokens.predecessor_hash` and
  `access_tokens.predecessor_refresh_hash`. A pair minted by `POST /refresh`
  records the hash of the refresh token presented.
* The presented token is not revoked when the pair is minted. The first
  successful use of the new access token (`authenticated_user`, which every
  authenticated route passes through) or of the new refresh token
  (`refresh_local_session`) revokes it.
* Presenting the same valid token again (the response was lost) mints a fresh
  pair and revokes the unused earlier one.
* Presenting a refresh token that is revoked — its successor was used, or it
  was ended by logout or a password change — revokes every access and refresh
  token of that device and writes an `auth.refresh.reuse_detected` audit row.
* Earlier access tokens of the device are still revoked at rotation, which
  the spec leaves to the server.

### Positive Consequences

* A lost refresh response can be retried, including across a restart.
* A refresh token stolen and replayed after the owner rotates is detected,
  and the session is ended for both parties.

### Negative Consequences

* A client that loses a response and then presents the token of that lost
  pair (rather than retrying the old one) ends its own session.

## Links

* Tests: `tests/conformance/test_client_server_conformance.cpp` and
  `tests/integration/test_persistent_homeserver_flow.cpp`
  (`[refresh_rotation]`); `tests/unit/test_homeserver_auth_service.cpp`
* `docs/auth-identity.md`
