# A device syncing online holds its account online against another device syncing unavailable

* Status: accepted
* Date: 2026-11-21

Technical Story: the owner's server logged `presence.outbound.refused` for every remote server, many times a second.
Two devices of one account were syncing at once, one with `set_presence` omitted (online) and one with
`set_presence=unavailable`. Each sync set the account's presence its own way, each change woke the other device's
long-poll, and the two flipped it every 50 to 250 ms. Each flip queued an `m.presence` EDU for each of about 470
servers, which filled the outbound dispatch queue and so refused every other federation send.

## Context and Problem Statement

A presence row is one per account, but `set_presence` is sent per sync, and so per device. The spec says "Any activity
that bumps the last active time on any of the user's clients will cause the server to automatically set their presence
to `online`", so a client in the background asking for `unavailable` should not take the account down while another
client is in use. How should the asks of several devices become one presence?

## Decision Drivers

* The account must not flip with each device's sync.
* A device that stops syncing must not hold the account online for ever.
* Memory stays bounded whatever the number of accounts and devices.

## Considered Options

1. Note each device's last ask in memory (`AccountPresenceTracker`). A device that asked for `online` holds the account
   online for `device_fresh_ms` (5 minutes, the idle timeout of ADR-0492). A sync asking for `unavailable` changes
   nothing while another device holds the account online, and never raises the account to online.
2. Keep one ask per account, the latest, as before.
3. Store the devices' asks in the database.

## Decision Outcome

Chosen option: 1, because it matches the spec's "any of the user's clients" and ends the loop at its cause.

* `set_presence=offline` forgets the device's ask: it no longer holds the account online.
* The freshness time is the idle timeout, so a closed client holds the account online exactly as long as the idle
  sweep would leave it online after that client's last sync; a `static_assert` in `PresenceService.cpp` keeps the
  two equal.
* At most `max_devices_per_account` (64) devices per account, the least recently seen replaced; at most `max_accounts`
  (65,536) accounts, pruned by the idle sweep every 30 s and when the table is full. An account with an open window
  (ADR-0872) is filed under its end, any other under the time its latest online device goes stale (a device that last
  asked for `unavailable` holds no place), so a prune visits only expired accounts, never the table: a flood of
  overflow requests under `runtime.mutex` costs no scan. With the table still full, the account with no open window
  whose devices go stale soonest is evicted to make room: it loses its devices' holds until it syncs again, never a
  window. Only when every account has an open window does a sync of an account the table does not hold have its device
  ignored and its change refused (ADR-0872), at most until the soonest window ends.
* The asks are in memory only: after a restart each device's next sync puts its ask back.
* The clock is the steady clock (`presence_limit_clock_ms`), which never goes back. The idle sweep measures activity on
  the wall clock (`observed_at_ms`), so after a wall-clock step the hold and the sweep disagree by the step until the
  device syncs again: after a backward step a background device's `unavailable` can win while the sweep still counts the
  user active, and after a forward step the sweep can set the account unavailable while a hold stands. Accepted: either
  is one change, limited by ADR-0872, never a loop. Judging the hold on the wall clock instead would let one clock step
  lift or extend every hold at once, and the `static_assert` keeps only the two durations equal.
* An account the table does not hold takes no place for a device asking for `unavailable`, so such a sync never evicts
  another account's hold.

### Positive Consequences

* Two clients of one account no longer set its presence back and forth.

### Negative Consequences

* After every online client closes, a background client asking for `unavailable` sets the account unavailable only
  once the freshness time has passed, up to 5 minutes later (the idle sweep sets it unavailable at the same moment).
* Option 2 is the simpler model, and looks better in isolation; it is the one that made the loop.
