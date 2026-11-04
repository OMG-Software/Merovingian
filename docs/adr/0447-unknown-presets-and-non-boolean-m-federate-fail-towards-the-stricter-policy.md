# Unknown presets and a non-boolean m.federate fail towards the stricter encryption policy

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`createRoom` accepts any `preset` string and gives an unknown one the private shape (invite-only, guests can join). `m.federate` in `creation_content` is passed through; the create-event auth rule only treats boolean `false` as non-federated.

## Considered Options

* Treat an unknown preset as public, or as federated only when `m.federate` is true
* Unknown preset is private; `m.federate` is non-federated only when it is boolean `false`

## Decision Outcome

Chosen option: the second. An unknown preset can never escape the policy as a public room, and a non-boolean `m.federate` counts as federated, matching the auth rule, so neither opens a way around `require_for_private_rooms` or `block_unencrypted_federated_private_rooms`.
