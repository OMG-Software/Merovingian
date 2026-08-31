Agreed. Fixed in `f77c7ee1`.

This was recorded as a known deviation when `/context` landed rather than hidden, but you are right that it should have been fixed properly — a context request around an older event exposed present-day values, so a room renamed or a power level changed after the target event showed today's state against yesterday's messages.

Reused rather than rebuilt: `federation::resolve_state_event_ids_at()` calls the same backward event-DAG walk (`reconstruct_state_at_event`) that the federation `GET /state` and `/state_ids` endpoints have used since 0.8.10. One deliberate difference on top — SS API `GET /state` stops *"prior to considering any state changes induced by the requested event"*, whereas CS API `/context` wants the state **at** the last event returned, so the pinned event's own state contribution is folded back in when it is itself a state event.

The test is built to actually distinguish the two implementations: a room's name changes strictly *after* the last event a bounded `?limit=2` window admits, and `state` is asserted to still carry the pre-rename name. A scenario where state never changed would have passed under both the old and new code and proven nothing.

**`GET /messages` is deliberately left unchanged, and that divergence is now recorded** in `docs/todos/capability-gaps.md` rather than left silent. Its `state` field has a different spec definition — *"a list of state events relevant to showing the `chunk`"*, which is what lazy-loading needs — so applying the position-reconstruction fix there would produce differently-wrong behaviour, not correct behaviour. Fixing one sibling and quietly leaving the other divergent seemed worse than a documented difference.
