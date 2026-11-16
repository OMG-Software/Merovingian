# Page text is escaped by type, and the page policy names only a validated redirect origin

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

## Context and Problem Statement

[ADR-0763](0763-the-authentication-pages-are-built-into-the-binary-without-javascript.md) requires that text reaches a
page only through the renderer's escaping. A rule that relies on every caller remembering to escape fails once.
Chromium also applies the `form-action` directive to the redirect that follows a form post, so the consent page's
policy must allow the client's redirect target, which comes from the request.

## Considered Options

* Types: `HtmlText` can be made only by `HtmlText::escape` or from an `HtmlLiteral`, whose constructor is `consteval`
  and refuses `& < > " '`; names, button values and `autocomplete` tokens are `HtmlName`, and a form action is a
  `PagePath`, both `consteval`. Page parts accept nothing else.
* A renderer that escapes every `std::string` it is given.
* Template text with placeholders.

## Decision Outcome

Chosen option: "Types". A page part cannot be given a `std::string`, so unescaped text does not compile. Escaping
replaces `& < > " '` and refuses text that is empty, longer than 4096 bytes, invalid UTF-8, or holds a control or
bidirectional formatting character; the caller chooses what to show instead. A detail value is wrapped in `<bdi>`.
A link is written only for an `https` URL that `ParsedUri::read` accepts. A form has one or two submit buttons with
distinct name and value pairs, and a password input never carries a value.

`page_headers()` sends `default-src 'none'; style-src 'sha256-…'; base-uri 'none'; frame-ancestors 'none';
form-action 'self'`, the hash computed from the one fixed style block, with `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and `Cache-Control: no-store`. `page_headers(target)` adds to `form-action` only
`ParsedUri::csp_source()` of the matched redirect URI: `scheme://host[:port]`, or `scheme:` for a private-use scheme,
built from fields the reader limited to characters that cannot end a source or a directive. As defence in depth it
adds nothing for an authority scheme other than `http` or `https`, or for a scheme without a `.`.

### Positive Consequences

* Forgetting to escape is a compile error, not a vulnerability.
* A hostile redirect URI cannot add a directive or a second source to the policy.

### Negative Consequences

* A page cannot show text with a bidirectional mark, or any text over 4096 bytes.
* Fixed text with an apostrophe or ampersand must be written without one, or escaped at run time.

## Pros and Cons of the Options

### A renderer that escapes every string

* Bad, because a string that was already HTML (a fragment built elsewhere) would be escaped twice, and the fix is a
  "raw" overload that brings the bug back.

### Templates

* Bad, because a placeholder in an attribute, a URL and element content each needs a different escape, and nothing
  checks that the right one was used.
