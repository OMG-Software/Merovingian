# Registration checks the username before UIA; a single-shot dummy stage still completes

* Status: accepted (amends ADR-0057 and ADR-0232)
* Date: 2026-10-29

Technical Story: Complement run 10 and 11 (`TestRegistration`, and every Complement blueprint that
registers users)

## Context and Problem Statement

`/register` ran User-Interactive Authentication before checking the username, while the spec says
"Homeservers MUST perform the relevant checks and return these codes before performing
User-Interactive Authentication" (`M_INVALID_USERNAME`, `M_USER_IN_USE`, `M_EXCLUSIVE`).

Complement's `Registration_without_a_session_fails` expects a dummy stage sent without a session to
be refused. A first fix in this branch made `m.login.dummy` complete only within a session the server
issued. Complement run 11 then showed Complement's own blueprints register users with exactly such a
single request (`auth: {type: m.login.dummy}`, no session), so every blueprint with users failed to
build.

## Considered Options

* `m.login.dummy` completes only within a session this server issued.
* A single-shot dummy stage completes; a session that is supplied must be one this server issued.

## Decision Outcome

Chosen option: the single-shot dummy stage completes, because the spec makes the session a client
duty only when one was given: "a session identifier that the client must pass back to the home
server, if one is provided, in subsequent attempts to authenticate in the same API call". A request
that was never challenged was given none. A supplied session that this server did not issue for the
endpoint is still refused with the 401 challenge. Complement's subtest, which Synapse, Dendrite and
Conduit skip for the same reason, is listed in `skip-list.toml` as non-spec.

The username checks run before UIA, as the spec requires, and again after it. Upper-case usernames
are still refused.
