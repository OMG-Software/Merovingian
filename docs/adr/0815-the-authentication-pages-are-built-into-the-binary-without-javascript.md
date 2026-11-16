# The authentication pages are built into the binary, without JavaScript

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

The OAuth 2.0 API ([ADR-0812](0812-the-oauth-2-0-api-is-built-into-the-homeserver.md)) makes the homeserver serve
pages to a browser: login, registration, consent and account management. The user types the account password into
them. Until now the server returned no HTML at all. Where do the pages come from?

## Decision Drivers

* A page that takes a password is the most valuable target on the server. Script injection there is account
  takeover.
* The main process is sandboxed after start-up. On FreeBSD it cannot open a file after `cap_enter`.
* The pages show text an unauthenticated party chose: the client's name and addresses from its registration.

## Considered Options

* Fixed HTML compiled into the binary, with no JavaScript.
* Template files on disk that an operator may edit.

## Decision Outcome

Chosen option: "Fixed HTML compiled into the binary, with no JavaScript". One renderer builds every page and
accepts only fragments that have been escaped. Every page is sent with a `Content-Security-Policy` that allows no
script and no remote resource. Branding is the server name and links from the configuration. A client's logo is
never fetched or shown.

Rules for future code:

* A page never contains a `<script>` element, an event-handler attribute or a `javascript:` address.
* Text reaches a page only through the renderer's escaping. Nothing concatenates a value into HTML.
* A page loads nothing from another origin.

### Positive Consequences

* The policy can be as strict as `default-src 'none'`, because nothing on a page needs more.
* Nothing is read from disk at request time, so the sandbox needs no new permission.

### Negative Consequences

* An operator cannot restyle the pages. A change of wording or appearance is a release.
* The pages cannot use client-side validation or progressive enhancement.

## Pros and Cons of the Options

### Template files on disk that an operator may edit

* Good, because an operator can match the pages to their site.
* Bad, because an edited template can drop escaping or loosen the policy, and the server cannot tell.
* Bad, because the templates must be read before the sandbox closes, and a reload could not re-read them.
