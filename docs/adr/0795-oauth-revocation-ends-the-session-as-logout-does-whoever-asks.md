# OAuth revocation ends the session as logout does, whoever asks

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 7 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md) (proposal P8)

## Context and Problem Statement

`POST /_merovingian/oauth2/revoke` takes a token, optionally its type hint and a client ID. The spec says the server
MUST revoke both tokens of the session, SHOULD revoke even when the client ID is missing or wrong, and lists a 401 for a
client "not authorised to revoke the token". What is ended, for which tokens, and when is the answer 401?

## Considered Options

* Revoke only the tokens, keep the device, and only for OAuth sessions whose client matches.
* End the session exactly as `POST /logout` does, for any live access or refresh token, whatever the client ID.

## Decision Outcome

Chosen option: the second.

* `revocable_session_of_token` finds the session by the token as a live access token or an unrevoked, unexpired
  refresh token; `token_type_hint` is ignored whatever its value. No session: 200 with an empty body.
* `end_device_session_and_announce` is the one shared path: `end_device_session` (`AuthService.cpp`, the former tail of
  `logout_local_user`) revokes every token of the device in one transaction, deletes the device and with it the
  `oauth_sessions` row, and audits; then the device leaves the runtime, local users sharing a room are told, and remote
  servers get `m.device_list_update` with `deleted: true`. `POST /logout`, revocation (`oauth.session.revoked`) and a
  replayed code (`oauth.code.replayed`, ADR-0792) all use it.
* A legacy token is revoked the same way: the token proves possession, as for `POST /logout`.
* There is no 401 case: a client that holds the token is authorised to revoke it, and no client authenticates
  (ADR-0791). Client credentials are refused as at the token endpoint.

### Negative Consequences

* A leaked token lets anyone end its session. That is the spec's intent ("help good actors like secret scanning
  tools"), and the holder could have used the token anyway.
