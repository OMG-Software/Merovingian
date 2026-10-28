# Login matches a user ID exactly, then downcased

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: Complement `TestLogin`, "Login with uppercase username works and GET /whoami
afterwards also".

## Context and Problem Statement

`POST /login` with `m.id.user` looked the identifier up exactly, so `@CAROL:example.org` or
`CAROL` did not log `@carol:example.org` in. The appendices give upper-case letters no place in
user IDs created today because "it should be possible to reach `@user:matrix.org` as
`@USER:matrix.org`", and require homeservers to downcase new usernames
([User Identifiers](../matrix-v1.19-spec/appendices.md#user-identifiers)). They also require
servers to accept historical user IDs, whose localparts may hold upper-case letters.

## Decision Drivers

* A user ID that differs only in case names the same user.
* An account with a historical upper-case localpart must still be able to log in.

## Considered Options

* Look the user ID up exactly; when no account has it, look up the ID with its localpart's ASCII
  letters downcased.
* Always downcase the localpart before looking it up.

## Decision Outcome

Chosen option: exact, then downcased. Downcasing always is simpler, but it would make an account
with a historical upper-case localpart unreachable by its own ID.

### Positive Consequences

* `@USER:server`, `USER` and `user` all log in `@user:server`.
* Historical accounts are unaffected.

### Negative Consequences

* Only ASCII letters are folded; a historical localpart that differs from a current one only in a
  non-ASCII letter's case is not matched, as it is not today.
