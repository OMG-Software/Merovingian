# A cross-signing reset approval is bound to the OAuth device that asked for it

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: review finding 3 on `feature/oauth-20-v110`. Amends
[ADR-0797](0797-an-oauth-session-replaces-its-cross-signing-keys-through-the-m-oauth-stage-and-a-one-use-approval.md)
and [ADR-0799](0799-the-m-oauth-stage-accepts-a-polling-retry-without-a-session-and-reuses-the-user-s-live-session.md).

## Context and Problem Statement

The approval the account page grants for `org.matrix.cross_signing_reset` (ADR-0797) is a per-user flag, and
ADR-0799 lets a replacing upload complete the `m.oauth` stage without naming a UIA session. Any of the user's OAuth
sessions can therefore spend it: a client the user forgot about, or one whose token was stolen, that keeps polling a
replacing upload replaces the user's cross-signing identity the moment the user approves a reset another client asked
for. The page cannot tell the user which device will use it. How is an approval tied to the device the user meant?

## Decision Drivers

* The spec's account management URL "MAY accept" `device_id`, "For Matrix-specific actions, the user's device ID.
  Actions which don't support the device ID will ignore it" (Client-Server API, "Account management URL parameters").
  `org.matrix.cross_signing_reset` is a Matrix-specific action, so the parameter may be carried on it; nothing requires
  a server to use it.
* A client that opens the URL without `device_id` (hand-built, or an older server's URL) must keep working.
* The page must never show a device the user does not hold, or confirm that another user's device exists.

## Considered Options

* Carry the requesting device in the challenge URL and bind the approval to it when the page can show it.
* Bind the approval to the UIA session the challenge issued.
* Keep the per-user flag.

## Decision Outcome

Chosen option: carry the device. The `m.oauth` challenge URL is `account_action_address(..., device_id)` with the
requesting device. When the reset page gets a `device_id` that names one of the signed-in user's own devices holding an
`oauth_sessions` row, it names the device and its client and carries the ID in its form; the approval is then bound
(`CrossSigningResetApprovals::approve(user, device, now)`) and `take(user, device, now)` gives it only to that device's
upload, which also restores it bound. Any other `device_id` (another user's, a legacy device, an unknown one, a
malformed one) is ignored and never shown: the page is the unbound one, which says in plain words that any application
signed in with OAuth can use the permission, and its approval behaves as before. A posted `device_id` that is no
longer one of the user's OAuth devices is refused with nothing approved, never widened into an unbound approval.

Binding to the UIA session was rejected because ADR-0799 accepts a retry with no session (clients poll that way), and
a session ID is not shown to the user anyway.

### Positive Consequences

* An approval given on the page a client opened can be spent by that client's device only.
* The user sees which device and which application the permission is for.

### Negative Consequences

* An approval the user gave on the unbound page is still usable by any of the user's OAuth sessions.

## Links

* Amends [ADR-0797](0797-an-oauth-session-replaces-its-cross-signing-keys-through-the-m-oauth-stage-and-a-one-use-approval.md)
  and [ADR-0799](0799-the-m-oauth-stage-accepts-a-polling-retry-without-a-session-and-reuses-the-user-s-live-session.md)
