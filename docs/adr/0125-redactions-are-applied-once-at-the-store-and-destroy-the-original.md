# Redactions are applied once, at the store, and destroy the original content

* Status: accepted
* Date: 2026-10-08

Technical Story: 29 September 2026 security audit, finding CSAZ-11 (redactions are accepted and
relayed but never applied). The project owner chose full redaction support, including
`PUT /rooms/{roomId}/redact/{eventId}/{txnId}`.

## Context and Problem Statement

`m.room.redaction` events arriving through `/send` or federation were relayed without a validity
check and never applied, so the original content was still served, and `PUT /redact` did not
exist. The spec ("Handling redactions", every room version from v3) says a redaction is sent to
clients and applied only once both events have been received and validated, and is applied when
the redaction's sender has the `redact` power level or shares the original sender's server
domain. It also says the stripped event "is thereafter returned anytime a client or remote server
requests it" and that redaction "cannot be undone, allowing server owners to delete the offending
content from the databases".

Where should a redaction be applied, how is it judged, and what happens to the original?

## Considered Options

* **Judge each redaction against its own `auth_events`, apply it once by overwriting the stored
  target from a store-level observer, and keep no copy of the original (chosen).**
* Keep the original and redact on every read. Rejected: every read path must remember to redact,
  and one that forgets serves the content the user removed.
* Hook each ingest path (local send, federation, worker relay, backfill, membership acceptors).
  Rejected: a future ingest path that forgets the hook silently stops applying redactions.

## Decision Outcome

Chosen option: judge once, apply at the store, destroy the original.

* **Judgement.** The `redacts` target is read from the top level for room versions before v11 and
  from `content` from v11. A redaction applies when its sender's power level, taken from the
  power-levels event among the redaction's own `auth_events`, is at least the `redact` level (v12
  creators count as infinite), or when its sender's domain matches the target's sender's domain;
  the target must be in the same room and the redaction must not be rejected or soft-failed.
  Using the redaction's own auth events means every server reaches the same verdict whatever
  state it has since.
* **Application.** `PersistentStore`'s redaction observer runs after every stored event, so every
  ingest path (local, federation, worker relay, backfill, membership) is covered without its own
  hook. A valid redaction overwrites the target's stored JSON with the room version's redaction
  algorithm output; read paths add `unsigned.redacted_because`. A redaction whose target has not
  arrived is held and applied when it does; one that does not apply is withheld from clients for
  good. The pass also runs once at startup, so redactions accepted by earlier builds are applied.
* **The original is destroyed.** No copy is kept for moderation. A future feature that needs the
  original (for example a moderation review queue) must capture it before redaction and get its
  own decision; do not add a copy of the original content anywhere.
* **`m.room.create` is never redacted.** Before v11 the algorithm strips `room_version`, which this
  server reads from that event; the spec is silent, and refusing keeps the room readable.
* **Local rule.** A local client may redact its own events, or any event with the `redact` power
  level; a server administrator may redact a local user's event (spec: "Server administrators may
  redact events sent by users on their server"). A suspended user may redact only their own.

### Negative Consequences

* Redaction cannot be undone, even by an administrator, and a mistaken redaction loses the content.
* The first start after upgrading applies redactions that older builds accepted, destroying that
  content.
* A redaction of a redaction event in v10 or earlier strips its `redacts`, so after a restart the
  original target, still redacted, loses its `redacted_because`.
