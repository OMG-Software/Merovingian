# A hand-off allowlist entry is an https origin or a bare private-use scheme, never a prefix

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: `server.oauth.hand_off_redirect_allowlist`, [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

A hand-off returns the user to an application the operator trusts. The allowlist names those applications. What
shape may an entry take, and how is a target compared with it?

## Considered Options

* An https origin (`https://app.example.org`, an optional non-default port) or a bare private-use scheme with its
  colon (`io.element.app:`), compared by origin or by scheme.
* A URL prefix, compared with `starts_with`.
* Any URL, compared byte for byte.

## Decision Outcome

Chosen option: the first. `oauth::hand_off_allowlist_entry_error` reads an entry with `ParsedUri::read` and refuses
anything else: a path (even `/`), a query, a fragment, userinfo, an explicit `:443`, an upper-case letter, a scheme
other than `https` with an authority, and a bare scheme with more than its colon or without a `.` (RFC 8252 section
7.1; this also refuses `http:`, `https:`, `javascript:` and `data:`). The list holds at most 32 entries, each once,
and is refused unless `server.oauth.enabled=true`. Entries are refused, never repaired.

### Positive Consequences

* A prefix match of `https://app.example.com` accepts `https://app.example.com.evil.example` and
  `https://app.example.com@evil.example`; an origin comparison cannot.
* One spelling per entry, so a duplicate or a case variant cannot hide in the list.

### Negative Consequences

* An operator cannot limit a hand-off to one path of an origin; the whole origin is trusted.
