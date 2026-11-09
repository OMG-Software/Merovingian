# A bind at an identity server grants nothing on this server

* Status: accepted
* Date: 2026-11-09

Technical Story: security audit run 4, finding F-02 (medium).

## Context and Problem Statement

`POST /account/3pid/bind` and the deprecated `POST /account/3pid` take only an access token, as the spec defines
them. Both also created the row in `account_threepids` that the unauthenticated password reset reads as proof that
an address belongs to the account. Anyone holding a stolen access token, without the password, could bind their own
email and then reset the password, which is exactly what the password step on `POST /account/3pid/add` prevents.

The spec separates the two: `GET /account/3pid` "is *not* the same as the list of third-party identifiers bound to
the user's Matrix ID in identity servers"; "Homeservers should track successful binds so they can be unbound later";
and "Homeservers should not prevent this request from succeeding if another user has bound the 3PID."

## Considered Options

* A bind records the bind and nothing else
* Require the password step on `/bind` too

## Decision Outcome

Chosen option: "A bind records the bind and nothing else", because it follows the spec's own separation and needs
no change to what a client sends.

A row in `account_threepids` is one of two things, told apart by `added_at_ms` (`is_account_threepid`):

* Non-zero: the address is on the account. It went through `POST /account/3pid/add` (or registration), is listed by
  `GET /account/3pid`, can reset the password, can receive email pushes, and is unique to one account.
* Zero: the address was only bound at an identity server. The row exists so the bind can be undone. It grants
  nothing, and any number of users may hold one, so `/bind` no longer asks `threepid_in_use`.

A bind never changes a non-zero `added_at_ms`, and `/add` promotes a bound-only row. `POST /account/3pid/unbind` of
an address on the account clears the bind and keeps the row; of a bound-only row it deletes the row, since nothing is
left for it to record. There is no schema change: the column already exists and the primary key is
`(user_id, medium, address)`.

Every reader that treats a row as ownership asks `is_account_threepid`: the password reset's request and completion,
`GET /account/3pid`, `owned_email_pusher_address` and `threepid_in_use`. A new reader does the same.

## Pros and Cons of the Options

### Require the password step on /bind

* Good, because it closes the takeover with one check.
* Bad, because the spec's `/bind` has no `auth` parameter, so a conforming client cannot complete it.
* Bad, because the address would still appear in `GET /account/3pid` and still be refused for a second user, both of
  which the spec says should not happen.
