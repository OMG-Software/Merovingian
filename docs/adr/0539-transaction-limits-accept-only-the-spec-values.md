# Transaction limits accept only the spec values

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

`security.federation.max_transaction_pdus` and `max_transaction_edus` accepted 1 to 50 and 1 to 100. The spec allows
a transaction of up to 50 PDUs and 100 EDUs, so any lower value makes `/send` refuse a legal transaction.

## Considered Options

* Remove the keys.
* Keep the keys and refuse any value other than 50 and 100 at parse time (owner decision 2026-11-07).

## Decision Outcome

Keep the keys, so existing configs still parse and the limits stay visible, and refuse every other value. Because the
upper bound is the spec value too, the only accepted values are exactly 50 and 100.

### Consequences

* A config that lowered either limit fails validation with a finding naming the key.
* If the spec ever raises a limit, change the constant and this record together.
