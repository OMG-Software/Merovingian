# The user directory reads the accounts once and caps its results

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-50 (and F-34's display name text): `POST /user_directory/search` scanned every account for every matching profile

## Context and Problem Statement

The handler walked `store.profiles` and, for every profile matching the term, ran `std::ranges::any_of` over all of
`store.users` to leave out deactivated accounts. A one-character term such as `@` matches every profile, so a
request cost accounts x accounts comparisons with `runtime.mutex` held. The result `limit` was any non-negative
integer and applied only after the scan.

## Considered Options

* Build the set of deactivated user IDs in one pass over the accounts and look each profile up in it
* Add an indexed user lookup to `PersistentStore`
* Stop matching after enough visible results

## Decision Outcome

Chosen option: "one pass into a set". `homeserver::matching_directory_profiles` reads `store.users` once into an
`unordered_set<string_view>` of deactivated IDs, then walks `store.profiles` once, matching display name and user ID
with the request's `core::FoldedSubstringMatcher` (ADR-0330) and skipping deactivated accounts.
`UserDirectorySearchStats` records the passes over the account table (1) and the profiles examined, so a test holds
the walks to a count that does not grow with the matches. The request's cost is now linear in the profiles, accounts
and text bytes the server holds, not in anything the caller multiplies.

`limit` is clamped to `max_user_directory_results` (100). The spec defaults it to 10 and gives no maximum;
`limited` says the list was cut, so a larger `limit` gets 100 results and `limited: true` when there were more. It is
a constant, not a configuration key: the output is bounded by it and no operator needs to move it.

An indexed lookup on `PersistentStore` was rejected for now: the set is built per request in one pass and no other
caller needs the index. Stopping after enough visible results was rejected because visibility is decided for the
whole candidate set at once (`directory_visible_users` builds its state index once per request), so the matching
pass cannot know which matches will be visible.

### Positive Consequences

* One request cannot cost accounts squared.

### Negative Consequences

* A client that asked for more than 100 users in one request now gets 100 and `limited: true`.
* The per-request cost is still linear in the number of local accounts; there is no early stop.

## Links

* Refines [ADR-0330](0330-search-terms-are-matched-in-linear-time-and-capped-at-1024-bytes.md)
