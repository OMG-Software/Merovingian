# A client key claim is capped like its federation twin and merges a remote answer by hash set

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit finding C13, a client `POST /keys/claim` merging a remote answer quadratically under `runtime.mutex`

## Context and Problem Statement

`POST /keys/claim` forwards every remote user it names to that user's server and, after the answer returns, merged each accepted
user into the response with a search over the users already in it. The client chose the number of users (about 40,000 fit in
the 1 MiB body), and a server the same attacker runs could answer for all of them, so the merge was N^2/2 comparisons with
`runtime.mutex` held. The federation `/user/keys/claim` already refuses a request over `federation::max_key_request_entries`
(ADR-0604). What bounds the client request?

## Decision Drivers

* The work under `runtime.mutex` must be linear in what the request names.
* A claim burns one-time keys, so a refusal must come before any key is claimed (the body is already validated whole first).
* One cap for both callers, so a client cannot do through its own server what a remote server cannot.

## Considered Options

* Reuse `federation::max_key_request_entries` (users plus devices) with `413 M_TOO_LARGE`, and merge by a hash set
* Only replace the search with a hash set
* A lower cap for clients than for federation

## Decision Outcome

Chosen option: "Reuse `federation::max_key_request_entries` with `413 M_TOO_LARGE`, and merge by a hash set".

`handle_key_claim` calls `federation::key_request_exceeds_entry_cap(body, "one_time_keys")` straight after the body parses, so
nothing is claimed for a refused request. The merge of each remote answer builds one `std::unordered_set` of the users the
response holds (once per remote server, at most 16) and inserts each accepted user into it, so a user already answered locally
is still never overwritten or repeated, and each entry costs one lookup.

### Rejected: only the hash set

The merge becomes linear, but the request still fans out to a remote server for 40,000 users and `accept_remote_key_claim_response`
still walks the answer; the cap bounds those as well.

### Rejected: a lower client cap

Real clients claim for the devices of the users in the rooms they share, a few thousand at most. A second constant would drift from
the federation one for no gain in protection.

### Negative Consequences

* A client naming more than 25,000 users plus devices gets a 413 instead of an answer. The cap is the one federated servers live with.
