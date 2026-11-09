# A redaction's authority comes from the state this server holds

* Status: accepted; supersedes the rule of [ADR-0125](0125-redactions-are-applied-once-at-the-store-and-destroy-the-original.md) that a redaction is judged on its own `auth_events`
* Date: 2026-11-09

Technical Story: security audit run 4, finding F-06 (medium).

## Context and Problem Statement

ADR-0125 judged a redaction on the `m.room.power_levels` event among its own `auth_events`, so that every server
reaches the same verdict. The sender chooses that list. A moderator who had been demoted could cite the older power
levels, and the auth checks accept an older but valid citation, so the target was redacted, which cannot be undone.

The spec's condition is only that "the sender's power level is at least the redact level"; it does not say at which
point in the room's state.

## Considered Options

* The level must be met in the state before the redaction and in current state
* The level must be met in the state before the redaction only
* Keep the event's own citation

## Decision Outcome

Chosen option: "both", because redaction is irreversible, so authority removed by either record should stop it.

`reconcile_redaction` applies a redaction only when `judge_redaction` says `applies` under both contexts. The domain
condition needs no state, so a redaction of a user of the sender's own server still applies in every case.

* The state before the redaction is its own state group: a redaction changes no state.
* `RedactionContext::power_levels_known` is false when that state cannot be read (no group yet, a broken chain, or
  state naming an event the store lacks), and then no sender meets the level. A room that really has no power levels
  event stays known, with the defaults.
* The observer also runs when a mapping is recorded (`apply_event_state_group`), because every ingest path stores the
  event first and the mapping after it, and the first call is too early to see the state.
* `check_local_redaction` uses current state: the event has no group yet.

### Negative Consequences

* Servers can disagree, which ADR-0125 was written to avoid: one that sees the demotion before judging withholds a
  redaction another applied. The disagreement is about whether a redaction is applied, not about the room's graph or
  state, and the safer side of it is the one that keeps the content.
* A redaction sent before its sender was demoted, and first judged afterwards, stays withheld.
* A redaction is judged again only when its event, its target or its mapping is stored, or at startup, so one withheld
  for lack of authority can apply after a restart if the sender regained it. Authority at the redaction is still
  required.

## Pros and Cons of the Options

### The level in the state before the redaction only

* Good, because the verdict does not depend on when it is reached.
* Bad, because a sender demoted on a fork this server has already resolved keeps the power to destroy content.

### Keep the event's own citation

* Good, because every server agrees.
* Bad, because it is the defect: the sender picks the evidence.
