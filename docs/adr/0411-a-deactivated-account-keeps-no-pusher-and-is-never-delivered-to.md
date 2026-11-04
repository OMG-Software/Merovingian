# A deactivated account keeps no pusher and is never delivered to

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-80 (a deactivated account's HTTP pushers keep sending
room message content to their gateway URLs)

## Context and Problem Statement

`POST /account/deactivate` revoked every token and poisoned the password hash but left the account's
pushers, and neither the delivery builder nor the retry re-check asked whether the recipient was still
active. After deactivation nobody can sign in to remove a pusher, so a pusher registered by a
compromised session kept receiving every notifying event of the account's rooms, content included.
Email pushers already skipped a deactivated account (`email_push.cpp`). ADR-0264 accepts, as an owner
decision, that pushers are removed only on a password change and not on logout or device deletion; that
is about accounts whose owner can still sign in to remove them.

## Considered Options

* Delete every pusher at deactivation, and also refuse a deactivated recipient where delivery is built
  and where a retry is re-checked
* Delete the pushers only
* Refuse a deactivated recipient only
* Also delete pushers on logout and device deletion

## Decision Outcome

Chosen option: the first.

* `deactivate_local_user` deletes every pusher of the account (`delete_pushers_of_user` with no kept
  device), forgets its email-digest entry and drops its queued retries (`PushRetryQueue::drop_pusher`,
  which matches the user, so another account's pusher with the same app ID and pushkey is untouched).
* `build_pending_push_deliveries` skips a recipient that fails `asserted_user_is_active`, and
  `pusher_still_registered` returns false for one, so a pusher that could not be deleted (a backend
  write failed; the deactivation itself has already succeeded and is not undone for it) and a retry
  queued before deactivation still send nothing. Both guards stay when the first holds: the deletion
  can fail, and a path that stores a pusher for a deactivated account later must not become a leak.
* Logout and device deletion are unchanged and still governed by ADR-0264. The user can list and
  delete pushers from another session after those.

### Positive Consequences

* Closing an account ends its notifications, as email pushers already did.
* The two guards make the rule hold whatever happens to the pusher rows.

### Negative Consequences

* Building deliveries reads the user table once per event, on the first recipient who has a pusher
  (a set of the users who exist and are not deactivated), not once per recipient: a per-recipient
  `asserted_user_is_active` scan would be recipients times users under `runtime.mutex` on every
  event of a large room. A recipient with no user row is not in the set, which is how
  `asserted_user_is_active` treats one too. The retry check keeps `asserted_user_is_active`: one
  lookup per retry, on the retry thread, bounded by the batch size.

## Links

* Related to [ADR-0264](0264-follow-complement-on-client-server-points-the-spec-leaves-open.md) (logout and device deletion keep pushers)
* Related to [ADR-0219](0219-email-pushers-mail-only-the-accounts-own-addresses-an-unread-count-in-a-delayed-digest.md) (email pushers skip a deactivated account)
