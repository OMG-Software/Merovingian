# A client key query reads device keys through the index and is held to the federation entry cap

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit finding C19, a client `POST /keys/query` scanning the device-key table once per requested user

## Context and Problem Statement

For each requested local user that asked for all devices (`[]`), the client `POST /keys/query` handler looped over every row of
`device_keys`. The body could name about 25,000 users, they need not exist, and a key that is not a user ID counts as local, so
one request cost users x table rows under `runtime.mutex`. ADR-0603 and ADR-0604 indexed and capped the federation twin
(`/user/keys/query`) only. How is the client handler brought in line?

## Considered Options

* Read the user's rows through `for_each_user_device_key` and refuse over `federation::max_key_request_entries` with `413 M_TOO_LARGE`
* The index alone
* The cap alone

## Decision Outcome

Chosen option: "Read the user's rows through `for_each_user_device_key` and refuse over the entry cap".

The handler counts the users and device IDs the body names with `federation::key_request_exceeds_entry_cap(body, "device_keys")`
before any lookup, and reads a local user's device keys with `database::for_each_user_device_key`, as the federation builder
does. The work is the rows of the users named, under a cap shared with federation.

### Rejected: the index alone

A 25,000-entry request would still do 25,000 index lookups and, per user, two cross-signing lookups and a display-name read; the
cap is part of the bound.

### Rejected: the cap alone

A request just under the cap would still scan the table for each of 25,000 users.

### Not changed

A key that is not a user ID is still treated as a local user and answered with an empty `devices` object, as before: the lookup
now costs nothing, so refusing it would only change what a client sees.
