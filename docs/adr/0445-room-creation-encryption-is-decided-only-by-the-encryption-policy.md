# Room creation encryption is decided only by room_creation_encryption_policy

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

The five `security.encryption.*` settings were parsed and documented as enforced, and nothing read them: `create_room` hard-coded "private presets get m.room.encryption" and treated any `m.room.encryption` entry in `initial_state`, whatever its state key, as the client having chosen. A private room could drop encryption with an entry under state key `x`. The Matrix API has no way to ask for an unencrypted room.

## Considered Options

* Keep the logic in `create_room`, reading the config there
* `rooms::room_creation_encryption_policy` takes the settings and decides; `create_room` only asks it

## Decision Outcome

Chosen option: the policy function is the ONLY place that decides, and it takes `config::EncryptionSecurityConfig` as input. `rooms::encryption_request_from_initial_state` reads the request: the last `m.room.encryption` entry that room creation would store under the empty state key (spec: `initial_state` events are sent "in the order that they are listed", so the last one is the room's state) is the request; it asks for encryption only if `content.algorithm` is exactly `m.megolm.v1.aes-sha2`, anything else is "unencrypted" (fail closed). An entry with a non-empty state key does not count, and an entry the loop would skip (no object `content`) does not count, so the policy judges the entry that becomes the room's state. A refusal is 400 `M_INVALID_ROOM_STATE`, judged in the preflight before any row is stored. `create_room` must not re-derive any of this; the default `m.room.encryption` is emitted only when the policy says encrypted and no effective entry exists.

Decision table (P preset, D direct, F can federate): required = (D and require_for_direct_messages) or (P private and require_for_private_rooms) or (P public and not allow_unencrypted_public_rooms) or (F and P private and block_unencrypted_federated_private_rooms); on by default = default_for_new_rooms and (P private or D); unspecified is encrypted when required or on by default; unencrypted is refused when required.
