# Application services assert only registered, active users, and never on Account Management

* Status: accepted
* Date: 2026-10-07

Technical Story: 29 September 2026 security audit, findings AUTH-7 (other services' exclusive
namespaces ignored), AUTH-8 (identity assertion honoured on 3PID management) and AUTH-12 (an
application service can act as a deactivated or non-existent user).

## Context and Problem Statement

The masquerade branch of `authenticated_user` checked only that the asserted user ID was in the
service's own user namespace. It did not look the user up, so a service could act as a user it
had never registered, or as one an administrator had deactivated. Register, login and assertion
also ignored other services' exclusive namespaces, and assertion was honoured on Account
Management endpoints, which the spec excludes ("This applies to all aspects of the Client-Server
API, except for Account Management").

The spec says users are created through `/register` with `m.login.application_service`, but does
not say what asserting a user that was never registered should do.

## Considered Options

* **Refuse assertion of a user that is not registered or is deactivated (chosen).**
* Allow unregistered users in the namespace and refuse only deactivated ones. Rejected: a
  service could then act as, and create rows for, users no registration ever vetted, and an
  administrator could not tell from the user list who a service acts as.

## Decision Outcome

Chosen option: refuse unregistered and deactivated users, as Synapse does.

* An asserted user (explicit `user_id`, or the implicit `sender_localpart` user) that is not
  registered, or is deactivated, is refused with `403 M_FORBIDDEN`. `POST /register` and
  `POST /login` are exempt: they act as the sender user, which is created at startup (AUTH-3),
  and check namespace ownership themselves. A bridge that asserts a puppet before registering it
  gets `403`, the signal to register first.
* A service may not register, log in as, or assert a user in another service's exclusive
  namespace: `/register` answers `400 M_EXCLUSIVE` (the status the spec's response table gives),
  `/login` and assertion `403 M_EXCLUSIVE`. An out-of-namespace `/register` also moved from 403
  to 400 for the same reason.
* Every path under `/_matrix/client/<version>/account` refuses a masqueraded request with
  `403 M_FORBIDDEN`, except `GET /account/whoami`, which the spec's own identity-assertion example
  uses. An unknown future `/account/...` path is refused too (fail closed).
* The checks run under the request lock in `handle_client_server_request`, and
  `authenticated_user` repeats the namespace, exclusivity and active checks as defence in depth.

### Negative Consequences

* Bridges that relied on asserting unregistered puppets must register them first.
* Device management (`/devices`, `/delete_devices`) still honours assertion; bridges use
  `device_id` masquerading, and the spec's Account Management section does not list them as
  endpoints.
