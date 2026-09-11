# Show an uploaded key signature only to the audience its uploader has

* Status: accepted
* Date: 2026-09-11

Technical Story: 0.12.10, "devices of users on other servers always show as
unverified".

## Context and Problem Statement

`POST /_matrix/client/v3/keys/signatures/upload` stores signatures that the
server later merges into the keys it publishes. The spec returns each key
"along with the signatures uploaded via /keys/signatures/upload that the
requesting user is allowed to see", and the federation variant "that the user
is allowed to see", without saying who may see what.

Before 0.12.10 every stored signature on a key was merged for every requester,
on the client path only, and whatever signer entries an upload carried were
merged, so an upload could put an entry under another user's name. Keys served
over federation got no uploaded signatures at all, which is half of why remote
users saw every device as unverified. A merge now had to be added to the
federation paths too, which forced the question: which signatures, for whom?

## Decision Drivers

* A device is only trusted by its owner, as far as anyone else can tell, if the
  owner's self-signing signature over it reaches them. Those must be public,
  including to remote servers.
* A user-signing signature over someone else's master key records that the
  signer verified that person. That is private to the signer. The signer's own
  client needs it back to show the person as verified.
* No upload should be able to speak for another user.
* One rule, applied identically on every path that serves keys, so the client
  and federation views cannot drift apart again.

## Considered Options

* Merge every stored signature for everyone (the old client behaviour).
* Merge only signatures uploaded by the key's owner, for everyone.
* Merge signatures uploaded by the key's owner for everyone, plus signatures the
  viewer uploaded themselves; a remote server is a viewer with no user; from
  each upload merge only the uploader's own signer entry.

## Decision Outcome

Chosen option: **the third**, implemented once in
`federation::merge_visible_key_signatures()`
(`include/merovingian/federation/key_signatures.hpp`) and used by client
`/keys/query`, federation `/user/keys/query` and `/user/devices/{userId}`,
outbound `m.device_list_update` and `m.signing_key_update`, and the master keys
the `/keys/query` federation proxy returns.

**The rule this sets for future code: never merge stored signatures into a key
by hand. Go through `published_device_keys()`, `published_cross_signing_key()`
or `merge_visible_key_signatures()`, and pass the real viewer — the requesting
user on client paths, `std::nullopt` for anything sent to another server.**

### Positive Consequences

* Remote servers get the owner's cross-signing signatures, so devices show as
  verified across federation.
* A user's own verification of another user, local or remote, comes back to
  them and to no one else, so the verified-user state persists without leaking
  who has verified whom.
* A forged entry under another user's name is never published.

### Negative Consequences

* The second option would be simpler, but it would drop the viewer's own
  user-signing signatures, and the user-verified state would never persist.
  That trade was rejected.
* Ownership is decided by who *uploaded* the signature, not by verifying it
  cryptographically. The signature bytes are still unverified at upload, as
  before this change. A client verifies every signature it relies on anyway.

## Links

* Related: [ADR-0061](0061-proxy-remote-cross-signing-keys-rather-than-caching-them.md)
