# A user holds a bounded number of live OpenID tokens, and a mint sweeps expired rows in one commit

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C37.

## Context and Problem Statement

Any local account could mint an OpenID token for itself at the generic client rate, so one account held about 36,000 live
rows, and each row lived an hour. The sweep every mint ran deleted each expired row with its own committed statement and
its own linear vector erase: measured at 94 seconds of `runtime.mutex` for one mint after an hour of minting.

## Considered Options

* Evict a user's oldest live tokens when a mint would pass `database::max_openid_tokens_per_user` (32).
* Refuse the mint past the cap.
* Keep sweeping every user's expired rows on each mint, but as one statement.
* Sweep only the minting user's rows on a mint, and everything else from the retention job.
* Sweep when a timer says it is due.

## Decision Outcome

Chosen options: evict, and sweep everything in one statement. `store_openid_token` writes the new row, one
`DELETE ... WHERE expires_at <= now` for all expired rows and a delete per evicted row in a single transaction, and only
then changes memory (erasing by swapping the last row into the gap, so the indexes of ADR-0681 stay valid).

Eviction was chosen over refusal because a widget or call client mints a token per session: refusing would leave a
user locked out for up to an hour by their own old tokens, while the oldest token of 32 is the one least likely to be
in use. The cap is 32 and is not configurable: a token is one-time identity proof for a third party, so no legitimate
client holds more than a few.

Sweeping every user's rows on a mint was kept, with its cost now one pass that allocates only when it finds an expired
row, because the existing contract (and its test) is that a mint reaps any user's expired rows. A user-only sweep or a
timer would leave other users' expired rows in the table until a retention job ran, and would change that contract. The
pass is linear in the rows held, which the cap bounds by users times 32; residual: an attacker who creates many accounts
raises the pass, but each account costs a registration, which is gated and rate limited.

## Links

* Refines [ADR-0681](0681-openid-tokens-are-found-by-an-index-of-token-hashes.md)
