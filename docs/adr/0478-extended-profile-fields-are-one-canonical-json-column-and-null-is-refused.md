# Extended profile fields are one canonical JSON column, and null is refused

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

Spec v1.16 adds `m.tz` and custom keys to the profile (`GET`, `PUT` and `DELETE /profile/{userId}/{keyName}`). The
profile as a whole must stay under 64 KiB. Where are the fields kept, what happens to `null`, and what bounds the
number of keys?

## Considered Options

* A `profile_fields (user_id, key_name, value)` table, one row per key.
* One `fields_json` column on `profiles` holding the extended fields as a canonical JSON object.
* Accept `null` and store it.

## Decision Outcome

Chosen option: the `fields_json` column, with `null` refused as `400 M_INVALID_PARAM`.

* The profile is read and measured as one object (the 64 KiB rule counts `avatar_url`, `displayname` and every field
  together), so a write needs the whole set anyway. One column is one atomic `UPDATE`, adds no table (the v1 schema's
  table count and its worker role grants stay as they are) and loads with the row. `displayname` and `avatar_url`
  keep their own columns: every existing reader (room membership events, the directory, push) uses them.
* The spec lets a server reject `null` and tells clients to `DELETE`. Over federation a `null` field means "unset"
  (`query/profile`: "exclude it from the response body or give it the value `null`"), so a stored `null` could not be
  told from an absent field once relayed.
* The 64 KiB limit already bounds the number of keys (a key and the smallest value take 6 bytes, so about 10,900
  keys); no separate count cap is added. A write parses and serialises at most 64 KiB under `runtime.mutex`, which is
  linear in a bounded input.
* Keys follow the Common Namespaced Identifier Grammar (1 to 255 bytes, `[a-z]` first, then `[a-z0-9-_.]`); `m.` is
  reserved, so `m.tz` is the only `m.` key a client may set. A key over 255 bytes is `M_KEY_TOO_LARGE`, any other bad
  key `M_INVALID_PARAM`. The value of `m.tz` must be a string; this server does not check it against the IANA
  database (the spec: "Servers MAY choose to validate").

### Negative Consequences

* Removing one key rewrites the column (at most 64 KiB).
* A future per-key permission or index (for example searching by `m.tz`) would need the table.

## Links

* Spec: Client-Server API, `PUT /profile/{userId}/{keyName}`; Server-Server API, `GET /query/profile`
