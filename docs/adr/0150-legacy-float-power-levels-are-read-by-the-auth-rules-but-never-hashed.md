# Legacy float power levels are read by the auth rules, but never hashed

* Status: accepted
* Date: 2026-10-15

Technical Story: 29 September 2026 security audit, finding EVT-12 (d) (room versions 3-5 are stricter
than the spec on scalar power-level values).

## Context and Problem Statement

`rooms/v3.md` (and v4, v5) says `m.room.power_levels` "accept values as floats": exponential notation is
applied, the value is truncated at the decimal point, and values outside binary64, Infinity and NaN are
rejected. v6 made Canonical JSON mandatory, which has no floats. The auth rules read only integers and
(v1-v9) integer strings, so a float level was treated as invalid.

A float never reaches the auth rules from the network today, though. Event IDs and content hashes are
computed with `serialize_canonical_strict`, and events are parsed with `parse_lossless`; both refuse
floats for every room version. Canonical JSON defines no encoding for a float, so the hash of such an
event is whatever the originating implementation's float formatting produced.

How far should conformance go?

## Considered Options

* **Make the auth rules read floats exactly as the spec says, for v3-v5 only, and keep hashing and
  parsing strict (chosen).**
* Also relax hashing and event-ID derivation for v3-v5 with a Python-compatible shortest float
  encoding, so Synapse-origin float events verify. Rejected: it copies one implementation's
  undocumented float formatting into the signature path, where a mismatch means a wrong hash.
* No change, recorded as a deviation. Rejected: the auth rules are the part the spec defines, and they
  are cheap to make conformant.

## Decision Outcome

Chosen option: auth rules only.

* `RoomVersionPolicy::power_levels_accept_floats` is true for v3, v4 and v5.
* `events::PowerLevelEncoding` replaces the `allow_string_values` flag: `integers` (v10+),
  `integers_or_strings` (v6-v9), `integers_strings_or_floats` (v3-v5), derived only through
  `events::power_level_encoding(policy)`. Its parameters default to `integers`.
* A float is truncated toward zero. Infinity and NaN are rejected, and so is a truncated value outside
  int64: the spec accepts any binary64, but no real power level needs more, and refusing fails closed.

### Negative Consequences

* An event containing a float still cannot be parsed for hashing, so it cannot be received over
  federation; the auth rules handle such content where it is already parsed (`parse_json`).
* Values beyond int64 that the spec would accept are refused.
