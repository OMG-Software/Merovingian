Correction to my reply above — that overstated the state of this fix, and I would rather flag it than let it stand.

`657be2ca` closed two of the three legs: custom `data` members are now persisted (`011_pushers_data_extra.sql`, schema version 11) and forwarded to the gateway intact. But the **registration** leg is still open: `parse_pusher_set_body()` in `client_server.cpp` does not yet capture the custom members from the incoming `POST /pushers/set` body, and `room_service.cpp` does not thread them into the `PushGatewayDevice`. `data_extra` currently appears nowhere in `client_server.cpp`.

So end-to-end this is **not yet fixed**: a client registering a pusher with custom data still loses it, now at the parse step rather than the storage step. The plumbing to carry it exists; nothing fills it.

Those two files were deliberately fenced off from that change because concurrent work owned them, which is how the gap arose. It is being closed now and I will confirm here when the round trip is proven by test rather than by inspection.
