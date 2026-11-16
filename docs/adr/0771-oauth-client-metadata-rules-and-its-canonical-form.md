# OAuth client metadata rules, and its canonical form

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

Client registration is unauthenticated (spec "Client registration", RFC 7591). The spec fixes some rules (`web` and
`native` must be supported, `none` must be supported, unknown grant and response types must be ignored, redirect URIs
must be validated) and leaves the rest to the server. Phase 4 derives the client ID from the accepted metadata
(proposal P2 in `docs/todos/oauth-2-0-api.md`), so the same metadata must always give the same bytes.

## Decision Outcome

The owner decided these rules on 2026-11-15; `ClientMetadata::validate` applies them:

* `client_uri` is required: `https` in lower case, no userinfo, no fragment, and a host that is a DNS name of at least
  two labels: not an IP literal (no brackets, no all-digit last label), not `localhost` and not under `.localhost`.
  It is compared in ASCII lower case.
* `application_type` is `web` (also when omitted) or `native`.
* `redirect_uris` is an array of at most 16 strings, each checked by the redirect URI rules
  ([ADR-0770](0770-oauth-addresses-are-read-by-a-strict-reader-of-our-own-and-matched-byte-for-byte.md)); a failure is
  `invalid_redirect_uri`. Duplicates collapse and the list is sorted.
* `grant_types` defaults to `["authorization_code"]`; `authorization_code`, `refresh_token` and
  `urn:ietf:params:oauth:grant-type:device_code` are known, others ignored, duplicates collapse. A list with no known
  value is refused, since such a client could do nothing.
* `response_types` defaults to `["code"]`; `code` is known. With `authorization_code`, `code` and a redirect URI are
  required.
* `token_endpoint_auth_method` is omitted or `none`: every client is public.
* `client_name` is 1 to 128 bytes of UTF-8 with no control character. The line and paragraph separators and the
  bidirectional formatting characters (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) count as control
  characters, because they can make one name display as another on the consent page. Text is refused, never
  stripped.
* `policy_uri` and `tos_uri` are `https` on the client URI's host or a subdomain, with no userinfo or fragment.
* `logo_uri`, localised keys (`name#lang`) and unknown keys are ignored and never registered: logos are never
  fetched ([ADR-0763](0763-the-authentication-pages-are-built-into-the-binary-without-javascript.md)), and one
  language is shown.
* A known key of the wrong JSON type, a repeated key, or more than 128 members is `invalid_client_metadata`.

The canonical form is the canonical JSON of the registration response's object without `client_id`: every registered
member, `token_endpoint_auth_method: "none"` included, lists in their fixed order. It does not depend on key order,
duplicate values or ignored members.

### Positive Consequences

* Identical registrations from every install of a client share one row.
* Nothing a client sends reaches a page or the canonical form unless a rule above accepted it.

### Negative Consequences

* A confidential client, or one with only an IP-literal or `localhost` client URI, cannot register.
* A client name in a script that needs a bidirectional mark to display correctly is refused.
