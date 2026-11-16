# The m.oauth stage accepts a polling retry without a session and reuses the user's live session

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 9 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), part 0. Amends
[ADR-0797](0797-an-oauth-session-replaces-its-cross-signing-keys-through-the-m-oauth-stage-and-a-one-use-approval.md).

Amended by [ADR-0809](0809-a-cross-signing-reset-approval-is-bound-to-the-oauth-device-that-asked-for-it.md) (2026-11-16): a
retry without a session completes the stage only with an approval that is unbound or bound to the retrying device.

## Context and Problem Statement

ADR-0797 completed the `m.oauth` stage of a replacing `POST /keys/device_signing/upload` only when the retry carried an
`auth` dict naming the session the challenge issued, as the spec's "OAuth authentication" section describes. Clients
built on matrix-rust-sdk are believed (from its source as recalled, not verified here) to resend the same upload with no
`auth` dict, about twice a second for up to two minutes, until it succeeds, which the reference server accepts. Under
ADR-0797 each such poll issued a fresh UIA session and none ever completed; sixteen polls filled the user's share of
the session pool. Older clients also look for the stage under its pre-standard name, `org.matrix.cross_signing_reset`.

## Decision Drivers

* The approval, not the session ID, is what authorises the replacement: it is a per-user flag that any of the user's
  OAuth sessions may spend once (ADR-0797), and the session ID is handed to whoever holds the access token. Demanding
  the ID adds no secret.
* A client that polls must not consume a UIA session per request, nor be able to fill the pool.
* The spec's form (`auth` with just `session`) keeps working, and nothing else about ADR-0797 changes: one approval,
  one stored upload, never a password from an OAuth session, never an approval for a legacy session.

## Considered Options

* Accept a retry with no session when an approval is live, and reuse the user's live session in the challenge.
* Keep requiring the session ID and only stop issuing a session per poll.
* Accept any retry, also one naming a session this server did not issue.

## Decision Outcome

Chosen option: the first.

* With a live approval, an OAuth session's replacing upload completes the stage when the request has no `auth`, an
  `auth` dict without `session`, or an `auth` dict naming a session this server issued to this user for the purpose
  `cross_signing_reset`; and its `type`, if present, is `m.oauth` or `org.matrix.cross_signing_reset`.
* An `auth` dict naming any other session, an `auth` that is not an object, a `type` or `session` that is not a string,
  or another `type` (a password stage) gets the challenge and never takes the approval. A password is never checked.
* The challenge names the session the request named when that is live, otherwise the user's newest live session for
  the purpose (`live_uia_session`), and issues a new one only when there is none. A user therefore holds at most one
  live session for this purpose: sixty polls before the approval cost one session, and a session lives ten minutes,
  so a poll more than ten minutes after the first issues the second. The per-user cap of 16 and the pool cap still
  apply to that issue.
* The challenge offers the pre-standard name as a second flow with the same parameters:
  `{"flows":[{"stages":["m.oauth"]},{"stages":["org.matrix.cross_signing_reset"]}],"params":{"m.oauth":{"url":U},"org.matrix.cross_signing_reset":{"url":U}},"session":S}`.

### Positive Consequences

* A polling client succeeds on its first poll after the user approves, and polling costs no new session.

### Negative Consequences

* With a live approval, the first replacing upload from any of the user's OAuth sessions spends it, whether or not that
  client showed the user the challenge. ADR-0797 already accepted this ("any of the user's OAuth sessions may use it");
  the session ID never narrowed it, since any OAuth session of the user could obtain one by asking.
* `POST /keys/device_signing/upload` is in the `/keys/` per-IP refinement, 120 requests a minute per client address and
  route in a fixed window: two polls a second from one address meet the limit exactly, so a client polling slightly
  faster, or behind an address shared with other clients, is answered 429 until the window rolls.

## Pros and Cons of the Options

### Keep requiring the session ID

* Good, because it is the spec's literal form.
* Bad, because a client that polls without `auth` never completes, and the user is left with a reset that cannot finish.

### Accept a retry naming a foreign session

* Bad, because a session this server did not issue is a malformed request; answering it with the challenge, as every
  other UIA endpoint does, keeps one rule for an unknown session.

## Links

* Amends [ADR-0797](0797-an-oauth-session-replaces-its-cross-signing-keys-through-the-m-oauth-stage-and-a-one-use-approval.md)
* Pool and per-owner cap: [ADR-0683](0683-uia-sessions-belong-to-an-owner-and-a-full-pool-refuses-instead-of-evicting.md)
