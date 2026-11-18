# An exception escaping one of the server's own pages is answered with a fixed error page

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: review finding 6 on `feature/oauth-20-v110`. Amends
[ADR-0803](0803-the-client-server-dispatch-boundary-answers-an-escaped-exception-with-a-500-and-logs-only-its-type.md).

## Context and Problem Statement

ADR-0803 answers every exception a client-server handler lets escape with a JSON `500 M_UNKNOWN` and the CORS headers.
A browser that opened the authorisation page, the device link page, the account page or a legacy SSO redirect that
hands off to those pages (ADR-0802) then shows raw JSON, served without the pages' Content-Security-Policy and framing
headers (ADR-0772, ADR-0784) and with a CORS header the pages never carry (ADR-0785). What should a page path answer?

## Considered Options

* A fixed HTML error page for the page paths, the JSON answer for every other path.
* The JSON answer everywhere (ADR-0803 as it stood).

## Decision Outcome

Chosen option: the fixed page. When the escaped exception came from a request the dispatcher routes to a page
(`request_serves_page` in `ClientServerRuntime.cpp`: `GET` or `POST` of `/_merovingian/oauth2/authorize` or
`/_merovingian/account` with the OAuth 2.0 API on, of `/_merovingian/oauth2/link` with the device grant on too, and
`GET` of `/_matrix/client/v3/login/sso/redirect` and `/_matrix/client/v3/login/sso/redirect/{idpId}` while the hand-off
is on), the answer is `oauth_error_page_response(500, ...)`: `page = true`, `oauth::page_headers()`, no CORS header,
and a fixed text that holds nothing of the exception. The test matches on the same path, method and configuration as
the routes, so a page path and its route cannot disagree. Every other path, the OAuth API endpoints that answer JSON
included, keeps ADR-0803's answer. The log line is unchanged.

### Positive Consequences

* A browser gets a page it can show, under the same headers as every other page.

### Negative Consequences

* `request_serves_page` restates the page routes; a new page route must be added to it.

## Links

* Amends [ADR-0803](0803-the-client-server-dispatch-boundary-answers-an-escaped-exception-with-a-500-and-logs-only-its-type.md)
