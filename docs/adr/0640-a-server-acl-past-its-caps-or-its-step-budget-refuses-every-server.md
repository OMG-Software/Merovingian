# A server ACL past its caps or its step budget refuses every server

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit run 2, `F-resource-exhaustion.server-acl.unbudgeted-glob-and-reparse-per-check`.

## Context and Problem Statement

Every inbound PDU, relayed PDU and receipt EDU asks whether the origin and the sender's server pass the room's
`m.room.server_acl`. Each check parsed the whole ACL event again and matched each pattern with a table whose cost is the
pattern length times the server name length. A room admin may write an ACL of up to 64 KiB, so one check could cost
about 22 ms, and main makes the check under `runtime.mutex`. What must the server do with an ACL too big to evaluate
cheaply, and what must the match cost?

## Decision Drivers

* Under the caps the answer must not change: the glob is the spec's `*` and `?`, case-insensitive, over the whole name.
* An ACL is a security control. An unevaluated pattern must never become an allow.
* A cache of parsed ACLs must be synchronised and bounded (ADR-0525), and a redaction rewrites an event under the same ID.

## Considered Options

* A two-pointer glob, a cap of 4096 patterns and 255 bytes per pattern, a 1,000,000-step budget per check; an ACL past
  a cap, or a check past the budget, refuses the server
* Ignore patterns past the caps
* Keep the table matcher and only cache the parse

## Decision Outcome

Chosen option: the first. `parse_server_acl` sets `ServerAclEvent::exceeds_limits` and empties both lists when the event
holds more than `server_acl_max_patterns` patterns (allow and deny together) or a pattern longer than
`server_acl_max_pattern_length`; `evaluate_server_acl` then answers deny with the rule `acl_limits`. A check that spends
`server_acl_max_glob_steps` glob steps over all its patterns answers deny with the rule `acl_budget`. The caps sit far
above any ACL seen in practice (a 64 KiB event holds about 3000 patterns of average length), and a real ACL spends about
the pattern count times the server name length, well under the budget for a name of ordinary length.

The two-pointer match remembers only the last `*`. It is linear for every ordinary pattern, but not for a contrived one
(many `?` before a literal that never matches), so the budget, not the algorithm alone, is the bound.

The parsed ACL is cached per ACL event ID in a mutex-guarded map of at most 256 entries that is emptied when full. An
entry records the JSON's size and hash and is used only while both match, because redaction rewrites the JSON under the
same event ID and a stale entry would keep enforcing a redacted ACL.

### Negative Consequences

* A room whose admin writes an ACL past the caps loses federation until the ACL is replaced. This is deliberate and
  applies only to an ACL no real room has.
* A server name of 255 characters checked against thousands of patterns can exhaust the budget and be refused. That name
  is the attacker's shape, not an operator's.

## Pros and Cons of the Options

### Ignore patterns past the caps

* Bad, because a deny pattern past the cap would be silently skipped and the banned server let in.

### Keep the table matcher and only cache the parse

* Bad, because the table cost (the measured 22 ms) is the glob, not the parse, and a cache does not help the first check
  of each new ACL event.
