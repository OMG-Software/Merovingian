Agreed. Fixed in `ad9a2b18`.

Worth naming the impact plainly: a user turning notifications off was told it had worked while the push destination stayed live and kept receiving their events. That is a privacy failure as much as a correctness one — the client has no way to detect it and no reason to retry.

The handler now checks the `delete_pusher` result and surfaces an error on a backend failure instead of returning `200 {}`, following the existing `dispatch_err` conventions rather than adding a new error path.
