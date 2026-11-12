# A resident's membership template content is rebuilt from an allow-list before it is signed

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

When a local user joins, leaves (or rejects an invite) or knocks on a room this server does not hold, the resident's
template is hashed and signed by this server as the user's own event. Only type, room_id, sender, state_key and
`content.membership` were checked, and most of `content` stayed, so the resident (the inviting server, for a rejection)
could add a `reason` or any key that clients then show next to the user's name (run-3 finding C18).

## Considered Options

* Rebuild `content` from an allow-list at the three sites
* Remove a deny-list of known keys (`reason`, `displayname`, `avatar_url`)
* Refuse a template that carries anything else

## Decision Outcome

Chosen option: "Rebuild `content` from an allow-list at the three sites", through one function,
`restrict_membership_template_content`, called straight after `claim_membership_event_template`. It keeps `membership`
and, for a join only, `join_authorised_via_users_server`, which the spec requires a resident to set for a restricted join
and which the join path still checks after the answer. The user's own `reason` (knock) and profile (join) are added after
it. A join template whose authorising user is on this server is refused before signing: the spec defines the field as a
user of the resident, and one of ours would have this server vouch for itself.

Why not a deny-list: a new content key is allowed by default, which is the defect. Why not refuse: a harmless extra key
from an otherwise honest resident would then fail the join; dropping it is what this server would have written itself.
