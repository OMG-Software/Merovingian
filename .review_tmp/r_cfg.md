Agreed. Fixed in `f77c7ee1`.

Push delivery ships disabled by default, so without documented keys an operator had no discoverable way to switch on a feature this branch spent most of its effort building — the wildcard reloadability entry was not enough to act on.

`server.push.enabled` (default `false`), `server.push.connect_timeout_seconds` (default `10`) and `server.push.total_timeout_seconds` (default `30`) are now in the configuration parameter reference in `docs/user-manual.md`, with a matching commented-out block in `config/merovingian.conf.example`. Defaults were read from `include/merovingian/config/config.hpp` rather than assumed.

Also closed the same omission for `server.oidc.*` and `server.identity_server.*`, which were equally absent — an earlier task had matched that precedent instead of fixing it. `server.oidc.*` was additionally missing from the reloadability table and now has its row.
