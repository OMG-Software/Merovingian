# The outbound client logs a URL without its query

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-76 (`obs.outbound-client-logs-request-url-unredacted`)

## Context and Problem Statement

`http::OutboundClient::perform` wrote `request.redirect_rejected`, `request.error` and `request.success`
with the request's URL as the `url` field. The logger redacts a value by the name of its field, or by
the text before the first `=` of a token, so a URL under the key `url` was never examined. The identity
server client puts `sid` and `client_secret` in the query of `getValidated3pid`; URL preview and the push
gateway client pass URLs a user chose. With `log_modules.outbound_client` at debug or trace and a console
or file sink, those secrets and URLs reached the log.

## Decision Drivers

* "Never log secret material" (`src/observability/AGENTS.md`).
* Redaction by content cannot know every name a user or an identity server uses for a credential.
* A diagnostic line needs only enough to say where a request went.

## Considered Options

* Log the scheme, host, port and path of the parsed URL; never the query
* Pass the URL through `observability::sanitized_http_target`
* Pass the URL through `observability::sanitized_audit_target`

## Decision Outcome

Chosen option: "scheme, host, port and path of the parsed URL". `perform` builds the logged string once,
from the `ParsedOutboundUrl` it already holds (`loggable_url`), and all three sites use it. Userinfo is
not a case: `parse_curl_url` refuses it. A new log site in the outbound client names the URL the same way.

### Positive Consequences

* No query value can reach a log, whatever its name or the caller.

### Negative Consequences

* A debugging reader no longer sees which query a failing request carried.
* A secret placed in the path rather than the query would still be logged. No caller does that: the
  identity and federation paths hold identifiers, and a preview or gateway URL's path is the user's own
  choice of a public URL.

## Pros and Cons of the Options

### `sanitized_http_target`

* Good, because it keeps the query's shape and redacts known names.
* Bad, because its marker list redacts `client_secret` but leaves `share_token`, `key` or `sig` in the
  URLs of users and push gateways.

### `sanitized_audit_target`

* Good, because it cuts the target at `?`.
* Bad, because it takes a target, not a URL with an authority; the parsed URL already gives the parts.

## Links

* Refines the redaction boundary in `docs/debug-logging.md`
