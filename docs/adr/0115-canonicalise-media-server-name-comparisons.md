# Canonicalise media server-name comparisons

* Status: accepted
* Date: 2026-09-29

Technical Story: 2026-09-29 security audit finding MED-5.

## Context and Problem Statement

The media repository routes download and thumbnail requests to either the local store or a remote fetch based on a string comparison of the request's `serverName` with the configured local server name. Matrix server names are case-insensitive in practice and the default federation port `:8448` is optional; treating `EXAMPLE.ORG:8448` as remote causes the homeserver to fetch its own media over federation, leaking local-only media IDs and wasting bandwidth.

## Decision Drivers

* Routing must treat case and default-port variants of the local server as local.
* The canonicalisation must match the federation layer's existing server-name normalisation so the same identifier has the same meaning everywhere.
* Remote media must still be fetched when the server name is genuinely different.

## Considered Options

1. Compare raw request `serverName` against `runtime.config.server().server_name` unchanged.
2. Normalise by lower-casing the host and stripping `:8448` before comparison.
3. Resolve both sides through the full server discovery pipeline before deciding local vs remote.

## Decision Outcome

Chosen option: "Normalise by lower-casing the host and stripping `:8448` before comparison", because it is the minimal normalisation that closes the routing leak while reusing the existing `federation::strip_server_port` helper. Full discovery is unnecessary for the local-vs-remote decision and would add network latency and failure modes to a path that should be strictly local.

### Positive Consequences

* Requests for `Example.ORG`, `example.org:8448`, etc., now serve local media directly.
* The normalisation is consistent with federation ACL and routing code.

### Negative Consequences

* A non-standard port other than `:8448` is not stripped; operators using custom federation ports must still supply the matching port in client requests.

## Links

* Related security-audit report: `docs/security-audit-report-2026-09-29.md` finding MED-5.
