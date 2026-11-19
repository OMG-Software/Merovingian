# The typing and receipts extensions keep their event wrapper

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

MSC4508 sends a room's typing state as a bare object, `{"user_ids": [...]}`, and says so against `/v3/sync`: "the
typing state is *not* wrapped in an `m.typing` ephemeral event". This server sends `{"type": "m.typing", "content":
{"user_ids": [...]}}`, and likewise `{"type": "m.receipt", "content": {...}}` for receipts. matrix-rust-sdk (Element X)
deserialises the extension's rooms as ephemeral events; a bare object fails, and the SDK treats that as a failed sync
iteration and retries at once, for ever.

## Decision Drivers

* No client in use may be put into a sync loop.
* The deviation must be visible to anyone reading the MSC beside the code.

## Considered Options

* Send the bare form the MSC describes, under both names.
* Send the bare form under the prefixed name (`org.matrix.msc4508.typing`) only, the wrapper under the bare name.
* Keep the wrapper under every name.

## Decision Outcome

Chosen option: keep the wrapper under every name (the owner's choice). It is a deviation from MSC4508 and, for
receipts, from the shape MSC4551 follows. Revisit when the SDKs read the bare form: then the second option serves both.

### Negative Consequences

* A client written to MSC4508 alone reads `content.user_ids` rather than `user_ids`.

## Links

* Part of [ADR-0865](0865-sliding-sync-reads-the-msc4186-request-forms-leniently-and-answers-extensions-under-the-names-they-were-asked-by.md)
