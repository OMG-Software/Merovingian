# The `oauth` module is pure, and carries the wire error beside `core::Error`

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

The OAuth 2.0 API ([ADR-0760](0760-the-oauth-2-0-api-is-built-into-the-homeserver.md)) needs PKCE, a scope parser,
redirect URI and client metadata validation and a page renderer. Every input is attacker-chosen, some are secrets,
and every refusal must name an OAuth `error` code (`invalid_scope`, `invalid_redirect_uri`, ...) as well as a
description. The coding rules return `std::expected<T, core::Error>` (spelt `std::variant` while the toolchain cannot
build `<expected>`), and `src/core/AGENTS.md` forbids error enums of a module's own. Where do these functions live,
and how does a refusal carry its wire code?

## Considered Options

* A module `oauth` of pure functions; a refusal is `OAuthRefusal`, a struct of the wire code string and a
  `core::Error`.
* The same functions in `src/homeserver/`, beside the handlers.
* An `enum class OAuthError` as the error alternative.

## Decision Outcome

Chosen option: "a pure `oauth` module with `OAuthRefusal`". The module holds no state, does no I/O and logs nothing,
so every function can be unit-tested and fuzzed alone, and no secret can reach a log from it. A refusal is
`std::variant<T, OAuthRefusal>`; `OAuthRefusal::error_code` is one of the constants in `OAuthErrorCodes.hpp`, and
`OAuthRefusal::error` is a `core::Error` whose message is fixed text, safe to send as `error_description`. This is
the shape `federation::PublicRoomsRefusal` already uses for a Matrix `errcode`. A function with nothing to say but
"no" returns `bool` or `std::optional`.

PKCE accepts only `S256`. A challenge must be the one canonical 43-character encoding of a 32-byte digest, so a
challenge no verifier can match is refused when the authorisation request arrives, not when the code is redeemed.

### Positive Consequences

* Handlers map a refusal to a response without a table: the code is already the wire value.
* The module links only `core`, `crypto`, `canonicaljson` and `auth`, and its fuzz targets need nothing else.

### Negative Consequences

* `error_code` is a string, so a misspelt code is not a compile error; use the constants.

## Pros and Cons of the Options

### The functions in `src/homeserver/`

* Bad, because `homeserver` links everything, so the validators could not be fuzzed or tested in isolation.

### An error enum

* Bad, because `src/core/AGENTS.md` forbids module error enums, and the enum would still need a table to its wire
  string.
