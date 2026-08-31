Agreed — but verified against the spec before acting, because getting this wrong in the other direction would silently break `@room` notifications for every user.

The check: `.m.rule.roomnotif` appears **nowhere** in `docs/matrix-v1.19-spec/`, zero occurrences across the entire spec directory. `.m.rule.is_room_mention` appears three times in `client-server-api.md`, which confirms the absence is meaningful rather than an artifact of the push-rules section being missing. `.m.rule.contains_user_name`, the other legacy body-scanning default, is absent from both the spec and our rule set.

Removed in `657be2ca`. It was a body-text-scanning rule from before `m.mentions`, and keeping it enabled meant any literal `@room` text triggered a highlighted notification when the sender had permission — even where `m.mentions.room` was absent and `.m.rule.is_room_mention` correctly did not match.

Covered by a new `tests/unit/test_default_push_ruleset.cpp` asserting the rule is no longer in the served default set and that literal `@room` body text alone no longer notifies.
