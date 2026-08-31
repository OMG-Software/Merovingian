Agreed. Fixed in `ad9a2b18`.

The blast radius is what makes this one worth the reorder: with `append:false` the removal targets pushers belonging to **other users** sharing that pushkey, so a `store_pusher` failure part-way through left those users with no pusher and no replacement — silently disabling notifications for people who had nothing to do with the request, while the requester saw a 500 and could retry.

Reordered so the replacement is persisted before any removal happens. That was chosen over wrapping both in a transaction because the store abstraction spans SQLite and PostgreSQL and the write path is an upsert-plus-delete against the in-memory mirror as well as the backend; ordering gets the important property — no window in which other users' pushers are gone with nothing in place — without introducing transaction semantics across that boundary. Tested that a failed `store_pusher` leaves the other users' pushers intact.
