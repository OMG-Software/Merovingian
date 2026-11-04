# An event is judged for ignored senders by sender first, and its JSON is parsed only for an ignored one

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`trust_safety::is_delivery_suppressed(ignored, sender, event_json_is_state_event(json))` evaluates its third argument
before the call, so every event of every timeline was parsed to learn whether it is a state event, for a viewer who
ignores nobody. `PushRuleUnreadClassifier::visible` already looks the sender up first (ADR-0207).

## Decision Outcome

Timeline readers (`/sync`, `/messages`, `/context`, `/search`, left rooms) ask `withheld_as_ignored(ignored, event)`
in `client_server.cpp`, which tests `ignored.contains(sender)` before it parses. The rule is the same one: a state event of an
ignored sender is still sent. A new timeline reader does the same and never passes `event_json_is_state_event(...)`
as an argument to `is_delivery_suppressed`. The sliding sync builder, which also needs the invite flag, keeps its own
classification and is unchanged.
