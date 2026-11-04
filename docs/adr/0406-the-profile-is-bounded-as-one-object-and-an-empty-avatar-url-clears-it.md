# The profile is bounded as one serialised object, and an empty avatar_url still clears it

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, F-63 (`PUT /profile/{userId}/displayname|avatar_url` stored a value of any size
up to the client body cap and any string as `avatar_url`).

## Context and Problem Statement

`PUT /_matrix/client/v3/profile/{userId}/{keyName}` says "the total profile MUST be under 64 KiB", lists
`400 M_PROFILE_TOO_LARGE` for a value that "would make the profile exceed its maximum allowed size of 64 KiB", and
says "For `avatar_url`, the value MUST be an MXC URI string". The handler checked neither. A displayname of up to the
client body cap (1 MiB by default) was stored, served by the unauthenticated `GET /profile`, copied into every
co-member's `m.presence` in `/sync`, and any string was accepted as `avatar_url`.

Three choices are not in the spec: how the "total profile" is measured, which error code a non-MXC `avatar_url`
gets (the response table names none), and what an empty string does.

## Considered Options

* Measure the serialised profile object (`avatar_url` and `displayname`, with the new value) and refuse at 64 KiB
* Cap each field on its own, small enough that the member event always fits
* Measure only the new value

## Decision Outcome

Chosen option: "measure the serialised profile object". The server stores exactly two profile fields
(`displayname`, `avatar_url`; it has no `m.tz` or custom fields), so the profile is the canonical JSON of
`{"avatar_url": ..., "displayname": ...}` with the new value in place of the old one, and a size of 65536 bytes or
more is `400 M_PROFILE_TOO_LARGE` with nothing stored. Measuring the object is what the spec's "total" means and it
is what `GET /profile` serves; it also covers a request that is small on its own but pushes the other field over.
Replacing a value with a smaller one is always allowed. A profile whose stored field cannot be serialised (ADR-0182
keeps such a profile usable) is measured as the raw byte lengths of both fields plus the 34 bytes of the object, so
that field never makes an unrelated update fail.

A non-MXC `avatar_url` is `400 M_INVALID_PARAM`: the spec's table has no code for it and `M_INVALID_PARAM` is the
common code for a parameter with the wrong value. The check is `media::mxc_uri_is_valid` (the spec grammar:
`mxc://<server-name>/<media-id>`, media ID of `A-Za-z0-9_-`).

An empty `avatar_url` string is still accepted and clears the avatar. The spec says the value "MUST be an MXC URI
string", which an empty string is not, but clients clear an avatar by sending `""` and the server stores the clear as
an empty field. Refusing it would leave a user unable to remove an avatar through this endpoint (`DELETE` is the
spec's way, but not every client uses it). This leniency is deliberate.

### Positive Consequences

* The stored profile, and everything copied from it, is bounded below 64 KiB.
* An avatar that is not a Matrix Content URI is never stored or relayed in `m.presence` and member events.

### Negative Consequences

* A display name between about 63 KiB and 64 KiB is stored (the spec allows it) but the `m.room.member` event
  that would carry it exceeds the 65536-byte event limit, so it is not copied into rooms; ADR-0182 already answers
  `200` and logs the room failure. The rooms keep showing the previous name. A smaller per-field cap would avoid
  this, but the spec only says "MAY impose size limits on individual fields"; a limit is a product choice and is
  left to a later decision.
* If the server gains `m.tz` or custom fields, they must be included in the serialised object this check measures.

## Links

* Related to [ADR-0182](0182-a-profile-change-succeeds-once-stored-and-reaches-only-rooms-whose-state-holds-the-user-joined.md)
