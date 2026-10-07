# Canonicalise media server-name comparisons

* Status: accepted
* Date: 2026-10-06

Technical Story: 2026-09-29 security audit finding MED-5.

## Context and Problem Statement

The media repository routes download and thumbnail requests to either the local store or a remote fetch based on a string comparison of the request's `serverName` with the configured local server name. Matrix server names are case-insensitive in practice and the default federation port `:8448` is optional; treating `EXAMPLE.ORG:8448` as remote causes the homeserver to fetch its own media over federation, leaking local-only media IDs and wasting bandwidth.

## Decision Drivers

* Routing must treat case and default-port variants of the local server as local.
* Only variants that name the same server may be merged. `example.org:8449` and `example.org` are different Matrix server names.
* Remote media must still be fetched when the server name is genuinely different.

## Considered Options

1. Compare raw request `serverName` against `runtime.config.server().server_name` unchanged.
2. Normalise by lower-casing the host and stripping `:8448` before comparison.
3. Normalise with `federation::strip_server_port`, which drops any numeric port.
4. Resolve both sides through the full server discovery pipeline before deciding local vs remote.

## Decision Outcome

Chosen option: "Normalise by lower-casing the host and stripping `:8448` before comparison", because it is the minimal normalisation that closes the routing leak. Option 3 was the first implementation and is rejected: it treats `example.org:8449` as this server and serves local media under another server's `mxc://` URI. `strip_server_port` suits server ACLs, which match host names only, not server identity. Full discovery is unnecessary for the local-vs-remote decision and would add network latency and failure modes to a path that should be strictly local.

### Positive Consequences

* Requests for `Example.ORG`, `example.org:8448`, etc., now serve local media directly.
* A request naming another port on the same host is still treated as remote.

### Negative Consequences

* The audit also recommended rejecting discovery results that resolve to this server's own listener. That is not implemented. A self-fetch cannot loop, because the federation media endpoint serves local media only and remote fetching is off by default (`security.media.remote_fetch_enabled`), but it still costs one outbound request.

* A non-standard port other than `:8448` is not stripped; operators using custom federation ports must still supply the matching port in client requests.

## Links

* Related security-audit report: `docs/security-audit-report-2026-09-29.md` finding MED-5.
