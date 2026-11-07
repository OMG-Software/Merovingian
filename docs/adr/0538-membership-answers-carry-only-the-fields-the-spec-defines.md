# Membership answers carry only the fields the spec defines

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

One builder wrote every `send_join`, `send_leave` and `send_knock` answer with `room_version`, `auth_chain` and
`state`, plus `origin` for `send_join`. The spec defines `{}` for v2 `send_leave`, `knock_room_state` alone for
`send_knock`, and `auth_chain`, `event`, `members_omitted`, `servers_in_room` and `state` for v2 `send_join`.
`room_version` and `origin` are in none of them. The v1 invite answer was the bare event, where the spec says
`[200, {"event": ...}]`.

## Decision Outcome

Each endpoint answers exactly its documented fields. `room_version` and `origin` are dropped from `send_join`, since
the spec lists neither in the 200 response; `MembershipAcceptResult::room_version` still feeds event parsing but is not
echoed. v1 invite answers `[200, {"event": <signed event>}]`.

### Consequences

* A peer that read `room_version` from a `send_join` answer must take it from `make_join`, where it is required.
* Do not add a field to these answers for one peer's convenience; the spec lists none.
