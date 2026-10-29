# m.login.dummy registration needs a session this server issued

* Status: accepted (amends ADR-0057 and ADR-0232)
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestRegistration/parallel/Registration_without_a_session_fails`,
`.../POST_/register_rejects_if_user_already_exists`, `..._usernames_with_special_characters`)

## Context and Problem Statement

`POST /register` with `auth: {"type": "m.login.dummy"}` and no `session` completed registration.
User-interactive authentication completes stages within a session the server issued. Separately,
`/register` ran UIA before checking the username, while the spec says "Homeservers MUST perform the
relevant checks and return these codes before performing User-Interactive Authentication"
(`M_INVALID_USERNAME`, `M_USER_IN_USE`, `M_EXCLUSIVE`).

## Considered Options

* Require a server-issued session for every stage, the registration-token stage included.
* Require it for `m.login.dummy` only, and keep the registration-token stage's one-request form.

## Decision Outcome

Chosen option: `m.login.dummy` completes only within a session this server issued; without one the
answer is 401 with the challenge. The registration-token stage keeps its one-request form, which
deployments and about 350 test call sites use. The username checks run before UIA, as the spec
requires, and again after it. Upper-case usernames are still refused.
