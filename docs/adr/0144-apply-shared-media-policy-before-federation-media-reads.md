# Apply the shared media policy before federation media reads

* Status: accepted
* Date: 2026-10-14

Technical Story: September 2026 security audit MED-7.

## Context and Problem Statement

The production federation media provider checked repository availability but
omitted the media decision used by client downloads. A genuine signed federation
request could therefore retrieve a clean, available SQLite-backed upload after
an administrator persisted a media-scope deny rule for its bare media ID.
Federation authentication and a servable record are necessary but insufficient
conditions for disclosure.

## Decision Drivers

* Preserve one implementation of media-rule and policy-server semantics.
* Refuse before repository resolution and media-byte I/O.
* Preserve runtime locking, safe blocking-I/O release and record revalidation.
* Keep authentication, successful multipart responses and stored data unchanged.

## Considered Options

* Reuse `media_policy_decision` inside the self-locking federation provider.
* Duplicate local-rule filtering in the federation dispatcher.
* Rely on the federation-wide hook or repository moderation state alone.

## Decision Outcome

Chosen option: reuse `media_policy_decision` after the provider has acquired its
runtime guard and published `RequestLockScope`, before repository resolution.
A denied decision returns the existing result type with status 403, empty media
content type and bytes, and the decision's public reason. The dispatcher retains
its existing JSON error mapping; successful downloads retain their existing
multipart construction. No schema, persisted-format, configuration or IPC change
is required.

Duplicating rules in the dispatcher would diverge from client policy and miss
other callers of the provider. Repository state does not encode persisted
trust-and-safety rules. A federation-surface decision is not a media-ID decision.
The shared helper also retains the existing media-surface policy-server hook,
including its explicit unavailable-result policy.

### Positive Consequences

* The production provider cannot bypass admission policy merely because a
  repository record remains available.
* The provider's existing lock-release and blob-read revalidation remain intact.
* Exact/wildcard rule semantics continue to come from the shared helper.

### Negative Consequences

* The media policy hook may add a synchronous policy round trip, as for client
  downloads; its existing implementation releases the runtime mutex.
* This admission check does not add strict cancellation for a rule changed while
  the hook or blob I/O is in progress. Repository removal/quarantine revalidation
  remains a separate existing control, not proof of policy-revocation atomicity.

## Verification and Scope

Two real SQLite integration scenarios use generated credentials, authenticated
admin operations, cached live peer verification material, genuine X-Matrix
signatures and the production federation HTTP dispatcher. Healthy downloads are
parsed and checked for exact media MIME/bytes before denial. The persisted-rule
scenario reopens SQLite to verify the rule, checks empty provider refusal and
signed JSON refusal, preserves a second upload and restores the first after
DELETE. The configured-unavailable-hook scenario has no injected policy callback;
its direct-provider checks distinguish the media hook from the already-enforced
federation-wide hook, and explicit fail-open restores the healthy download.

The genuine pre-repair RED completed 129 assertions: 116 passed and 13 expected
refusal checks failed. Final normal-target GREEN completes 132 assertions in
two cases; related normal media integration passes 371 / 9, locking 146 / 7,
federation media conformance 12 / 1, client policy 41 / 3 and trust-safety units
100 / 13. Independent source review passes with no blocking security or logic
findings. The fresh normal full suite completes 56 OK with every return code
zero, fresh archived JSON/text logs reconciled, and 1,026 frozen files unchanged
including all 32 focused bindings and the reviewed source/registration bindings.

This accepts the bounded admission decision. No live remote-policy HTTP
response, raw socket federation transport, restart/hydration behavior or
mid-request policy revocation is claimed, nor is whole-pass or release acceptance.
