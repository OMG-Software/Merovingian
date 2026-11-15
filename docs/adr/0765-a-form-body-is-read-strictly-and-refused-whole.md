# A form body is read strictly and refused whole

* Status: accepted
* Date: 2026-11-15

Technical Story: phase 1 of the OAuth 2.0 API plan (`docs/todos/oauth-2-0-api.md`)

## Context and Problem Statement

The OAuth 2.0 token and revocation endpoints and the authentication pages read `application/x-www-form-urlencoded`
bodies. Their values are credentials: passwords, authorisation codes, refresh tokens, PKCE verifiers. The existing
query parser, `core::parse_query_params`, is lenient by design: it keeps a malformed escape literal and takes the
first of two parameters with the same name. Which rules should the form reader follow?

## Decision Drivers

* A body that two readers can understand differently is how a check is bypassed: one reads the first `client_id`,
  another the second.
* The input is unauthenticated and comes from browsers and native clients alike.
* A conforming encoder (the HTML form submission algorithm, the OAuth libraries Element X uses) escapes every byte that
  is not printable ASCII and never repeats a parameter the OAuth specifications define.

## Considered Options

* Reuse `parse_query_params` / `query_parameter`.
* The WHATWG URL Standard parser (skip empty fields, a field without `=` has an empty value, keep the first or the
  last repeated name).
* A strict reader that refuses the whole body on any departure from the grammar.

## Decision Outcome

Chosen option: "a strict reader", `core::FormFields::parse`. A malformed `%` escape, a field with no `=`, an empty name,
an empty field (`&&`, a leading or trailing `&`), a raw byte outside `!`..`~` (a raw space included), a decoded NUL,
decoded bytes that are not UTF-8, and a name sent twice (compared after decoding) each refuse the whole body. A literal
`=` after the first in a field belongs to the value. `+` is a space. An empty body is an empty set. Caps of 64 KiB of
body, 64 fields, 64 bytes of decoded name and 8 KiB of decoded value are refused, never cut. Errors carry fixed text,
and the parsed fields are wiped when destroyed.

### Positive Consequences

* No body has two meanings, so a check and a use always see the same value.
* A handler gets either every field, decoded and valid UTF-8, or one refusal it answers with `invalid_request`.

### Negative Consequences

* A sloppy client that sends a raw space or a repeated parameter is refused where a lenient server would serve it.
  The OAuth specifications require the encoding this reader expects.

## Pros and Cons of the Options

### Reuse `parse_query_params`

* Good, because it exists.
* Bad, because a malformed escape and a repeated name are accepted, and changing that would change every query route.

### The WHATWG parser

* Good, because it is what browsers implement for `URLSearchParams`.
* Bad, because it accepts every input, so a repeated name is resolved silently, which is the ambiguity to avoid.

## Links

* Refines [ADR-0760](0760-the-oauth-2-0-api-is-built-into-the-homeserver.md)
