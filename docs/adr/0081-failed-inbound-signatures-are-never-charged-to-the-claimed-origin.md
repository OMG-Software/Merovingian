# Failed inbound signatures are never charged to the claimed origin

* Status: accepted
* Date: 2026-09-29

Technical Story: finding FED-4 in `docs/security-audit-report-2026-09-29.md`
(forged X-Matrix requests lock a real peer out of federation until restart).

## Context and Problem Statement

The H-04 fix made `check_inbound_request_signature` increment
`consecutive_failures` on the *claimed* origin's trust record whenever a request
signature failed, so that a stream of bad requests would trip the backoff.
`remote_trust_policy` runs before the signature check and answers 429 once the
count reaches 3, and only an accepted request reset it. Nothing decayed it.

The origin in an `X-Matrix` header is whatever the sender wrote. It is
authenticated only by the very check that had just failed. Three unauthenticated
packets naming `peer.example` therefore made this server refuse every genuine
request from `peer.example`, and because a genuine request was now unreachable,
the count could never be reset. The lockout lasted until restart.

Whose account should a failed signature be charged to, and how long may a
backoff last?

## Considered Options

* Keep charging the claimed origin, but add time-based decay.
* Charge the claimed origin only when the source address is also known to
  belong to it.
* Charge the source network address, and never the claimed origin.

## Decision Outcome

Chosen option: "charge the source network address, and never the claimed
origin", because it is the only option in which an unauthenticated sender can
hurt no one but themselves.

* A failed X-Matrix signature check is counted against the address the
  transport saw (`SignedFederationRequest::remote_addr`, resolved through
  `trusted_proxies` and IPv6 prefix grouping, the same value that budgets
  key resolution). Beyond `RuntimeFederationConfig::bad_signature_per_ip_rate`
  (default 30 per 60 s) that address is answered 429 `M_LIMIT_EXCEEDED` before
  any signature work. Other addresses are unaffected. The container is capped
  and FIFO-evicted because it is reachable before authentication.
* The check runs in the main process, which is where signatures are verified
  (#323). The federation worker only handles requests main has already
  verified, so it never charges or consults this budget.
* `consecutive_failures` on a remote's trust record is charged only for
  failures after the signature has verified (malformed or oversize
  transactions, forged relayed PDUs), which the peer's own key caused.
* The consecutive-failure backoff decays: it is ignored once
  `remote_backoff_decay_window` (5 minutes) has passed since the last recorded
  failure, and a failure recorded after a quiet period starts again from one.
  Quarantine, an open circuit and low reputation are administrative states and
  do not decay.

### Negative Consequences

* A genuine peer that shares a source address with an attacker (CGNAT, or a
  reverse proxy without `trusted_proxies` configured, which collapses every
  peer onto the proxy's address) is throttled with them for up to the window.
  The blast radius is that address, not the named origin. Operators behind a
  proxy must configure `trusted_proxies`, as the key-resolution budget
  already requires.
* Decay means a peer that keeps sending bad transactions is refused for at most
  five minutes at a time, not permanently. Its refusals are still rate limited
  by the per-origin budgets.

## Pros and Cons of the Options

### Keep charging the claimed origin, but add time-based decay

* Good, because it is a small change.
* Bad, because the attacker only has to send three packets every five minutes
  to keep a real peer refused. Decay bounds the outage, not the attack.

### Charge the claimed origin only when the source address matches

* Bad, because there is no reliable mapping from an origin to its source
  addresses: federation peers move, sit behind proxies and share hosts.

### Charge the source network address, and never the claimed origin

* Good, because the only unauthenticated attribute that is not merely
  asserted in a header is the address the connection came from.
* Bad, because of the shared-address case above.

## Links

* Rule for future code: never write to a remote's `RemoteTrustState` from a
  code path that has not verified that remote's signature.
* Refines the H-04 fix (per-PDU trust failures survive a transaction), which
  is unchanged: those failures follow a verified signature.
* Related: #487 key-resolution budget (`docs/threat-model.md`).
