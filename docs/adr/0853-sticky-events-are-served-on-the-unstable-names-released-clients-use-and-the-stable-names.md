# Sticky events are served on the unstable names released clients use and the stable names

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

Sticky events (MSC4354) are message events that every server in a room keeps delivering to clients, and to the other
servers, until they expire. MatrixRTC uses them for call membership in Element Call's `matrix_2_0` mode: the membership
is an `org.matrix.msc4143.rtc.member` event sent sticky for one hour, and the leave is a delayed sticky event. The MSC
merged into matrix-spec-proposals (merge commit `fd4a696e42`). It is not in the vendored v1.19 specification. Which
names does the server accept and emit?

The released clients and Synapse, read at their release tags on 2026-11-18, use only the unstable names:

* Element Call 0.28.2 (matrix-js-sdk `3f05dc4d`) sends `?org.matrix.msc4354.sticky_duration_ms=` on
  `PUT .../send/{eventType}/{txnId}`, also together with `org.matrix.msc4140.delay` for the delayed leave. It reads the
  PDU field `msc4354_sticky`, `unsigned.msc4354_sticky_duration_ttl_ms` and `rooms.join.{roomId}.msc4354_sticky.events`
  in `/sync`. It refuses `matrix_2_0` mode unless `/versions` has `unstable_features["org.matrix.msc4354"]`. Its
  default mode, `compatibility`, uses state events and needs none of this.
* Element X (matrix-rust-sdk `b93751e9`, ruma `5133d4ec`) syncs only with sliding sync and enables the extension
  `org.matrix.msc4354.sticky_events` by default. ruma can put the query parameter on `/state` as well as `/send`.
* Synapse `develop` (`1b0fd0ab`) writes and reads only `msc4354_sticky` on PDUs, emits only the unstable `/sync` key
  and sliding-sync extension, and accepts the parameter on `/state`. The MSC no longer lets a client send a sticky state
  event; Synapse removed that in PR #20256.

## Decision Outcome

Serve every name a released client or Synapse uses, plus the MSC's stable names. A name the server emits is emitted in
both forms; a name it reads is read in either form.

| What | Stable | Unstable |
|---|---|---|
| Query parameter on `PUT .../send/{eventType}/{txnId}` | `sticky_duration_ms` | `org.matrix.msc4354.sticky_duration_ms` |
| Body field of `PUT .../delayed_event/{eventType}/{txnId}` (MSC4140, both prefixes) | `sticky_duration_ms` | `org.matrix.msc4354.sticky_duration_ms` |
| Top-level PDU field | `sticky: {"duration_ms": N}` | `msc4354_sticky: {"duration_ms": N}` |
| Remaining time, in `unsigned` | `sticky_duration_remaining_ms` | `msc4354_sticky_duration_ttl_ms` |
| Classic `/sync` section | `rooms.join.{roomId}.sticky.events` | `rooms.join.{roomId}.msc4354_sticky.events` |
| Sliding-sync extension (request and response) | `sticky_events` | `org.matrix.msc4354.sticky_events` |
| `/versions` | none | `unstable_features["org.matrix.msc4354"]` |

The rules:

* **Duration.** The value is a decimal integer of at least 1, in milliseconds, given at most once and in at most one of
  the two names. Anything else is `400 M_INVALID_PARAM`. A value above one hour is accepted and capped when the expiry
  is computed ([ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md)).
* **Message events only.** The parameter on `PUT .../state/...`, `POST .../send` or `PUT .../redact/...`, and the body
  field together with `state_key` on the delayed-event path, are `400 M_INVALID_PARAM`. They are refused rather than
  ignored, because ignoring them would let a client believe it sent a sticky event.
* **Disabled.** With `server.sticky_events.enabled = false` the parameter is `403 M_FORBIDDEN` and the
  `unstable_features` flag is `false`. The request is never sent as an ordinary, non-sticky event.
* **Composing.** A locally composed sticky event carries both `sticky` and `msc4354_sticky`, with the same object
  `{"duration_ms": N}` and N exactly as the client gave it. Both are top-level, so both are covered by the content hash
  and both are removed by redaction in every room version, which is what the MSC asks.
* **Reading a PDU.** An event is sticky when it is not a state event and carries `sticky` or `msc4354_sticky` whose
  `duration_ms` is an integer of at least 1. If both fields are present they must be equal; otherwise, or when the
  value is malformed, the event is accepted as an ordinary, non-sticky event.
* **Serving.** Both `unsigned` fields are added to an unexpired sticky event on every endpoint that serves it, and left
  out once it has expired. Neither is ever zero or negative.
* **Sliding sync.** The extension is read under either name; the response uses the name or names the request used.
* `content.sticky_key` and `content.msc4354_sticky_key` are content and the server ignores them.

## Consequences

* A `/sync` response carries each sticky event twice when it falls outside the timeline, once under each key. The
  section is bounded ([ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md)).
* A server that reads only the stable name, and one that reads only the unstable name, both see this server's sticky
  events.
* When the clients move to the stable names, the unstable forms can be removed by a later ADR that supersedes this one.

## Links

* Related: [ADR-0823](0823-delayed-events-are-served-on-the-stable-unstable-and-query-parameter-forms-that-released-clients-send.md)
* Related: [ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md)
* Related: [ADR-0855](0855-sticky-events-reach-clients-once-per-sync-position-and-in-full-on-joining-or-entering-scope.md)
* Related: [ADR-0856](0856-a-server-pushes-its-own-unexpired-sticky-events-to-a-server-that-joins-and-records-only-accepted-ones.md)
