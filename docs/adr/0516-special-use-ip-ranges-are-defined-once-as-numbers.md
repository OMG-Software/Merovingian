# Special-use IP ranges are defined once, as numbers

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

The loopback, RFC 1918 and ULA blocks were written down twice in `src/` and
`include/`. The default `security.federation.deny_ip_ranges` list spelled them as
strings, and `is_private_or_loopback_range()` compared a configured range against
the same six strings. `private_ip_range_is_allowable()` held the private blocks a
third time, as numbers. The two string copies could drift apart, and the string
comparison treated `fc00:0::/7` as a different block from `fc00::/7` although both
name the same network.

## Considered Options

* Keep the two string lists and add a test that they agree.
* Keep one numeric table and derive the strings and the comparison from it.

## Decision Outcome

Chosen option: one numeric table in `src/config/Config.cpp`. It holds the six
blocks as address bytes and prefix length, with a flag for the ones
`allow_private_ip_ranges` may name. The default deny list is built from it by
`default_federation_deny_ip_ranges()`, `is_private_or_loopback_range()` parses a
range and compares it by value, and `private_ip_range_is_allowable()` filters the
same table. Adding or changing a block means editing one row.

Keeping the string lists was rejected: it leaves two copies that can drift, and
comparing spellings depends on how an operator writes an address.

### Positive Consequences

* The deny list and the validation check cannot disagree about which blocks exist.
* Any valid spelling of a block is recognised.
* No address literal for these blocks is left in `src/` or `include/`.

### Negative Consequences

* The default list is built at run time rather than written as a literal, so a
  reader must look at the table to see the six strings.
