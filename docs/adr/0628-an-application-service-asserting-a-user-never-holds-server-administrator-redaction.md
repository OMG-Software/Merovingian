# An application service asserting a user never holds server administrator redaction

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, low findings, `F-chain.operator-authority.appservice-assertion-actions-attributed-to-admin`.

## Context and Problem Statement

[ADR-0611](0611-an-administrator-route-refuses-an-application-service-asserting-a-user.md) makes `require_admin` and
`authenticated_admin_user` refuse a masquerade token. That closes every operator route and every client administrator
route, and so closes the finding's attribution gap: an operator action is recorded only under the administrator whose own
credential made it, and the audit and `admin_actions` rows are written from the value those two functions return.

Reading every place that decides whether a user is a server administrator found one more. `send_event_as_user` judged the
server-administrator override for redacting another local user's event from the user record alone, so a bridge asserting
an administrator inside its namespace could redact any local user's event without the `redact` power level.

## Considered Options

* `send_event` tells `send_event_as_user` whether the token was a masquerade, and the override is not applied for one.
* Resolve the question once in `send_event` through `authenticated_admin_user`.
* Accept it: the redaction is an event in the room, attributed to the asserted user.

## Decision Outcome

Chosen option: the first. The override is a server-administrator authority, and ADR-0611's rule is that an application
service acts for the users of its namespaces in rooms, never as a server administrator. The asserted user's ordinary room
authority (own events, the `redact` level) is unchanged. The second option was rejected because the profile propagation
job calls `send_event_as_user` with no token and should keep the answer it has.

Every other read of `LocalUser::admin` in `src/homeserver` goes through `authenticated_admin_user` or `require_admin`.
