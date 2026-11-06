# A documented configuration key is enforced or removed, and redaction keys only accept true

* Status: accepted (supersedes [ADR-0051](0051-document-inert-configuration-keys-rather-than-removing-them.md) for `server.identity_server.allowed_bind_domains`)
* Date: 2026-11-04

## Context and Problem Statement

ADR-0051 kept `server.identity_server.allowed_bind_domains` as a documented-inert key. An audit of every parsed
setting found three more that nothing in `src/` reads: `server.identity_server.default_server`,
`security.logging.structured`, and (read only by start-up validation, which refuses `false`)
`security.logging.redact_tokens` and `security.logging.redact_event_content`. What should a key do that the code does not
act on?

## Considered Options

* Keep documenting inert keys as inert (ADR-0051).
* Enforce the key where the behaviour is real and simple, remove it where it is not, and refuse the unsafe value of a
  key whose safe value is what the code always does.

## Decision Outcome

Chosen option: the second. A key that looks like a control and does nothing is worse than an absent key.

* `allowed_bind_domains` is enforced. The Matrix error `M_THREEPID_DENIED` exists for exactly this ("the server only
  permits, for example, email addresses from a particular domain"). Empty restricts nothing; matching is on the exact
  domain after the last `@`, ignoring ASCII letter case; **subdomains do not match** (an allow list entry is a
  decision about one domain, and a suffix match would let `evil.example.org` ride on `example.org`). msisdn has no
  domain and is not restricted. The key is **not** a limit on every email a user may add: `POST /account/3pid/add`
  verifies locally and binds nothing on an identity server, so it is outside this key. An entry that is empty or holds
  `@`, `*` or whitespace can never match and is a start-up configuration finding, because failing closed at request
  time would refuse every email with no explanation. The check runs before any identity server is contacted, on every path that tells an
  identity server an address: email `requestToken` delegation, bind, and 3PID room invites.
* `default_server` is removed. It was documented as "used when a client omits `id_server`", but an omitted `id_server`
  means this server verifies the 3PID itself, and an identity server cannot be asked without the client's own
  `id_access_token`, which the spec ties to `id_server`. There is no correct behaviour to implement.
* `security.logging.structured` is removed: the logger has one format.
* `redact_tokens` and `redact_event_content` stay, accept only `true`, and are refused at start-up when `false`. No
  code path honours `false`. They must not be "enforced" by adding a switch that turns redaction off.

A removed key is now an unknown key, which the parser reports as a configuration finding (`unknown configuration key`)
and start-up refuses.

## Consequences

* An operator who still sets `default_server` or `structured` gets a start-up error naming the key.
* A future change that wants a redaction switch must supersede this record.
