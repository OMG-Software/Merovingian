# Device authorisations and user codes are held in memory, capped, and guessing is throttled per address

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: plan P5 and P11, phase 10 in `docs/todos/oauth-2-0-api.md`.

## Context and Problem Statement

A device authorisation holds two secrets. The device code is 256 random bits and only the device sees it. The user
code is typed by a person, so it is short: RFC 8628 section 6.1 suggests eight characters from twenty consonants,
about 34.5 bits. Anyone can type at the link page, so the user code's strength is the throttle on wrong codes, and
the store holding them is reachable without authentication. How are the entries kept, how is a user code drawn and
read, and how is guessing bounded?

## Decision Drivers

* Nothing an unauthenticated caller does may grow memory without bound or evict another user's sign-in.
* A user code must be uniform over its alphabet, and unique among the live entries.
* RFC 8628 section 6.1 asks the server to accept a user code however it is typed (case, dashes, spaces).
  `src/oauth/AGENTS.md` rule 2 says a reader refuses and never normalises.
* The retention sweep and the registration cap must not delete a client that a live device authorisation names
  (ADR-0780), and must answer that in O(1).
* No test may sleep.

## Considered Options

For the throttle at its own capacity:

* Fail closed: an address with no window waits until the soonest window ends.
* Fail open: an address with no window is not counted.
* Evict the oldest window.

For the user code reader:

* Normalise case and the separators `-`, space, `.` and `_`, and refuse everything else.
* Refuse anything but the stored form, as rule 2 says.

## Decision Outcome

* **In memory, as the other OAuth stores** (P5, ADR-0782): `DeviceAuthorisationStore`
  (`HomeserverRuntime::oauth_device_authorisations`) keeps entries in a `HashedSecretTable` under the hash of the
  device code; a second index maps the hash of the user code to the entry. Neither code is kept in clear except the
  user code inside the entry, which the consent page shows. A restart ends every sign-in in progress and nothing else.
* **Caps.** 4096 entries in all and 8 per client address key (`rate_limit_client_key`). At a cap the expired entries
  are purged and the creation is refused if it is still full; a live entry is never evicted. Every operation first
  removes the expired entries, soonest first, at the cost of the entries removed.
* **The idle-client walk bound** (`database::max_idle_client_rows_examined`) grows from 16'896 to 20'992 by the 4096
  entries, because each can name a different client the walk must skip. The registration and retention
  `static_assert`s include the new cap.
* **Retention.** `oauth_client_has_pending_authorisation` also asks `holds_live_entry_for_client`, which reads the
  latest expiry of the client's entries from a per-client index: O(1), no scan.
* **User codes.** Eight characters from `BCDFGHJKLMNPQRSTVWXZ` by rejection sampling: a byte below 240 gives the
  character at its value modulo twenty, a byte of 240 or more is skipped, so each character is equally likely. One
  draw takes 32 random bytes; a code that clashes with a live one is drawn again, at most 8 times, then the creation
  is refused (`secret_unavailable`, a 500). The store takes a `RandomSource` so a test can force a clash.
* **The reader normalises, as an exception to `src/oauth/AGENTS.md` rule 2.** `normalise_user_code` reads a lower-case
  letter as its capital and skips `-`, space, `.` and `_`; any other byte (a digit, a vowel, a letter outside the
  alphabet, a control or non-ASCII byte) refuses the whole text, as does text over 32 bytes or with other than eight
  characters left. The exception is required by RFC 8628 section 6.1 and is the only one in the module; the reader is
  still bounded and its error is fixed.
* **The throttle.** `UserCodeAttemptThrottle` (`HomeserverRuntime::oauth_user_code_attempts`) counts wrong codes per
  client address key in a window of ten minutes from the first wrong one. Five wrong codes block the address until
  the window ends: the page then answers 429 with `Retry-After` before the code is looked up, so the right code is
  refused too and a blocked guesser learns nothing. With 4096 live codes in a space of 20^8, five guesses in ten
  minutes find one with a chance of about 8 in 10^7 per address per window. A typed code that does not read as a code
  counts as wrong; a post without the browser cookie is not counted (it guesses nothing). The block is logged once, as
  `oauth.device.throttled` with `client_key`, at warning level.
* **The throttle fails closed at its cap** of 8192 windows: an address with no window waits until the soonest window
  ends. Failing open would let a flood of addresses lift the limit for itself; evicting the oldest window would let it
  lift the limit for the address it evicts. The cost is that such a flood blocks every other address's first try for
  up to ten minutes, which an operator sees in the log.
* **The clock.** Every store and throttle operation takes the time. The handlers pass `oauth_device_clock_ms`, the wall
  clock plus `HomeserverRuntime::test_device_grant_clock_advance_ms`, which only tests set.

### Positive Consequences

* The store's memory is bounded, a flood from one address cannot fill it, and no sign-in in progress is lost to one.
* A user code is uniform, unique while live, and accepted as people type it.

### Negative Consequences

* Behind a shared address (a carrier NAT, an office), five wrong codes from anyone block everyone there for ten
  minutes, and eight sign-ins at once from that address are the most it gets.
* A flood of distinct addresses past 8192 delays every address's first code.

## Links

* [ADR-0780](0780-oauth-registrations-are-capped-and-idle-clients-are-evicted-least-recently-used-first.md),
  [ADR-0782](0782-pending-authorisations-and-authorization-codes-are-in-memory-hashed-bounded-and-never-evicted.md),
  [ADR-0804](0804-the-device-authorization-grant-answers-rfc-8628-and-a-redeemed-device-code-is-expired.md),
  [ADR-0806](0806-a-device-sign-in-warns-first-creates-no-account-and-runs-in-one-browser-at-a-time.md)
* RFC 8628 sections 5.1, 5.2 and 6.1
