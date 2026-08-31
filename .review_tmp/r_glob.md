Agreed. Fixed in `657be2ca`.

This was a known caveat noted in the code comments when the evaluator landed, and you are right that it should not have been left there. The display name went straight to the glob matcher, so `*` and `?` in a legitimate name were treated as wildcards — a user whose display name is `*` was highlighted on every message in the room. More importantly a display name is user-controlled, so it could be chosen deliberately to force notifications onto other people's messages.

Compared as literal text now, and tested in both directions: a name containing `*` does not match a body lacking the literal name, and an ordinary name still matches.

Related, from your separate comment: `b350195f` also changed the source of that name to the recipient's `m.room.member` state for the room rather than the account-wide profile.
