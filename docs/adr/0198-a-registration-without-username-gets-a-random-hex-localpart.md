# A registration without a username gets a random hexadecimal localpart

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, R12 (registration rejected an omitted username)

## Context and Problem Statement

Spec (`POST /_matrix/client/v3/register`, `username`): "If omitted, the homeserver MUST generate a
Matrix ID local part." The server answered `400 M_BAD_JSON` instead. The spec does not say how to
generate the localpart, only that the returned user ID must conform to the user identifier grammar.

## Decision Drivers

* A generated user ID must not reveal how many accounts the server holds or when one was made.
* It must never land in an application service's namespace, on a reserved localpart, or on an
  existing account.
* It must satisfy `auth::localpart_is_valid_new`, the grammar every new account is held to.

## Considered Options

* 64 bits from the CSPRNG (`crypto::secure_random_hex(8)`), as 16 lowercase hex characters
* A sequential number
* A random word or name pair

## Decision Outcome

Chosen option: "64 random bits as 16 lowercase hex characters". A candidate that is reserved,
already registered, inside an exclusive application-service namespace or an application service's
sender is drawn again, up to 8 times; failing that, or if the random source fails, the request is
answered `500 M_UNKNOWN`. The generated localpart then takes the same path as a chosen one (grammar,
reserved names, appservice namespaces, registration token, rate limits). An explicit
`"username": ""` is still refused with `400 M_INVALID_USERNAME`: only an absent `username` is an
omission. The `m.login.application_service` registration still requires a username, because a
generated one would fall outside the service's namespace.

### Positive Consequences

* Generated IDs disclose nothing about the account count or registration order.
* A collision is negligible at 64 bits, and the retry covers it anyway.

### Negative Consequences

* Generated IDs are not memorable; a client that wants a readable ID must send `username`.

## Pros and Cons of the Options

### A sequential number

* Good, because it is short.
* Bad, because it discloses the number of accounts and lets anyone enumerate generated users.

### A random word or name pair

* Good, because it is readable.
* Bad, because it needs a word list, has a much smaller space, and can produce offensive pairs.

## Links

* Spec: `docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3register`
