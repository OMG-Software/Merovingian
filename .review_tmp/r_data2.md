Now genuinely closed, in `ad9a2b18` — following up on my correction above.

`parse_pusher_set_body()` captures every custom member of the incoming `data` object, `POST /pushers/set` persists them, `GET /pushers` returns them, and the pusher → `PushGatewayDevice` conversion threads them into delivery. `url` and `format` stay excluded per spec.

Proven end to end rather than per-leg: `tests/integration/test_push_delivery_flow.cpp` — *"custom pusher data members survive registration, GET /pushers, and reach the push gateway's notify request"*. That shape was deliberate. The gap existed precisely because storage, forwarding, and parsing each looked correct in isolation while nothing connected them, so a test proving only that the parse step populates the field would have repeated the same mistake one seam over.
