# A client PUT of m.room.encryption must carry the listed algorithm

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`PUT /rooms/{roomId}/state/m.room.encryption` accepted `{}`, a non-string `algorithm` or an unknown one. `room_is_encrypted` reads a room as encrypted only when `content.algorithm` is a string, so a member with power to send the event could turn a room's encryption off with `{}`. The spec makes `algorithm` "Required", "One of: `[m.megolm.v1.aes-sha2]`", and the common error `M_BAD_JSON` covers "missing required keys, invalid values for keys".

## Considered Options

* Refuse the body on the local client PUT only
* Also refuse it on federation ingest
* Make encryption one-way (refuse any replacement that is not encrypted, or any change)

## Decision Outcome

Chosen option: refuse on the local client PUT only. For event type `m.room.encryption` (any state key), a body whose `algorithm` is missing, not a string, or not exactly `m.megolm.v1.aes-sha2` is 400 `M_BAD_JSON`, and nothing is stored. The check runs after the body is known to be a JSON object and only for a sender who may send the event, so anyone else still gets the send path's 403. `rooms::encryption_algorithm_is_valid` is the only place that names the algorithm; createRoom's effective-entry reading uses it too, and createRoom's behaviour is unchanged. Appservices use the same client PUT and are covered. Extra fields such as `rotation_period_ms` stay accepted.

Federated events are not judged. The authorisation rules do not look at this event's content, so refusing a remote event for it would make this server disagree with others about room state. A remote server can therefore still send such an event, and `room_is_encrypted` can still read false in a federated room. Events stored before this rule are not migrated.

### Rejected alternatives

* Refusing over federation: breaks agreement on room state, the rules being content-blind for this event.
* One-way encryption: the spec does not say that encryption cannot be changed, so refusing replacements would be a rule the spec does not state.

## Links

* Related to [ADR-0445](0445-room-creation-encryption-is-decided-only-by-the-encryption-policy.md) and [ADR-0446](0446-the-encryption-settings-apply-to-room-creation-only.md)
