# Limit presence status messages by UTF-8 byte length

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Matrix v1.19 specifies presence states and shared-room disclosure, but does not bound status message size. The retained presence snapshot must have a finite per-user payload budget.

## Considered Options

* Accept at most 1024 UTF-8 bytes in status_msg and refuse an oversized update before allocating a sync stream position. Rejecting preserves the existing state; truncating silently would change user text.
* Use the general request-body ceiling as the only bound; silently truncate oversized text.

## Decision Outcome

Accept at most 1024 UTF-8 bytes in status_msg and refuse an oversized update before allocating a sync stream position. Rejecting preserves the existing state; truncating silently would change user text.

### Consequences

The limit is local policy, not a Matrix protocol maximum. Clients receive 400 / M_INVALID_PARAM and can shorten their status.
