# OpenID tokens are found by an index of token hashes

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C37.

## Context and Problem Statement

`GET /openid/userinfo` needs no account, yet main answered it under `runtime.mutex` by hashing the presented token and
comparing it with every row of `openid_tokens`. Access tokens, refresh tokens and sessions are found through indexes;
this table was a bare vector, so the cost of an unauthenticated request grew with the rows other users had minted.

## Considered Options

* A `RowKeyIndex` over `openid_tokens` by token hash and a `RowGroupIndex` by user, kept by every writer and rebuilt on load.
* A separate `database::CredentialTable` for OpenID tokens.
* Keep the scan and only cap the rows.

## Decision Outcome

Chosen option: the two row indexes (ADR-0603's pattern). `find_openid_token` costs one lookup per candidate hash (at most
three key versions); `federation_openid_userinfo` confirms the row it returns with the constant-time comparison, as the
other credential lookups do. The indexes are trusted only while built for the vector's current row count, so a test that
edits the vector directly gets a scan until the next writer rebuilds. Every writer (`store_openid_token`,
`revoke_openid_tokens_for_user`) calls `sync_openid_indexes` first, and both store loads call
`rebuild_openid_token_indexes`.

A `CredentialTable` was rejected: it is built for tokens that carry a device and a predecessor chain, and this table has a
user and an expiry only. Capping alone was rejected because a cap bounds a user, not the number of users.

## Links

* Refined by [ADR-0682](0682-a-user-holds-a-bounded-number-of-live-openid-tokens-and-a-mint-sweeps-expired-rows-in-one-commit.md)
* Follows [ADR-0603](0603-key-and-edu-lookups-go-through-position-indexes-and-an-edu-is-read-only-so-far.md)
