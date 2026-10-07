# Remote media fetches run on their own pool, one fetch per remote file

* Status: accepted
* Date: 2026-10-07

Technical Story: Element Web could not show an encrypted image a federated user
sent. Its log showed `[429] too many concurrent remote media fetches` for
`GET /_matrix/client/v1/media/download/matrix.org/…`, while the image's other
download was in flight. Supersedes the media part of
[ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md).

## Context and Problem Statement

ADR-0079 bounded every client request that makes this server call another one,
because each of them held a main request-pool thread for the whole round trip:
half the pool across all clients, and **one per client address**. Over either
cap the answer is `429` at once.

Remote media does not fit that bound. Element Web loads an image and its
thumbnail in parallel (`Promise.all`), and every remote image on screen at
once; a browser behind one address therefore always has more than one remote
media request in flight. All but the first were refused, Element does not
retry a media `429`, and the attachment stayed broken. The remote media cache
(ADR-0114, ADR-0119) helps only after a file has been fetched once.

How can a client load several remote files at once without letting a peer that
never answers stall the main request pool?

## Decision Drivers

* A normal client's first view of a room with remote media must work.
* Half the main request pool must stay available to requests that never leave
  this server, whatever a remote peer does (ADR-0079's driver, kept).
* A refused request must still cost nothing: no waiting on a main-pool thread.
* Two requests for the same remote file must not both fetch it: the second
  admission displaces the first's stored copy (`plan_remote_media_admission`),
  and a request still reading that copy then fails.
* A request must not be counted twice by the rate limiter.

## Considered Options

* **Hand the request to a dedicated media fetch pool, as a waiting `/sync` is
  handed to the sync pool, and coalesce fetches of the same file (chosen).**
* Raise the per-client cap within the main-pool budget (for example to half the
  global cap). Rejected: the fetch still holds main-pool threads, so the cap
  stays a trade between protecting the pool and serving clients, and a room full
  of images still exceeds any cap small enough to protect it.
* A separate per-client cap for media only, inside the same budget. Rejected for
  the same reason.
* An asynchronous, non-blocking rewrite of the fetch (event loop over
  `curl_multi`). Rejected for now: it changes the outbound client, the request
  lock and the response path at once. The pool gives the property that matters —
  no main-pool thread waits on a peer — with the handoff the transport already
  has.
* Queue over-cap requests on the main pool. Rejected as in ADR-0079.

## Decision Outcome

Chosen option: "Hand the request to a dedicated media fetch pool".

* **Where the fetch runs.** `RemoteMediaFetchScope` publishes, for the request's
  thread, how a remote fetch may run (`inline_fetch`, `defer`, `admitted`), as
  `RequestLockScope` publishes the request lock. A request on the main pool runs
  in `defer` mode: `fetch_remote_media_live` does everything that is quick —
  the `remote_fetch_enabled`/`allow_remote` refusal, the cache lookup, the
  trust-and-safety policy — and on a cache miss records a deferral and returns.
  `handle_client_server_request` turns the deferral into
  `DispatchResult::Status::needs_media_fetch`, and the transport hands the
  connection to the media fetch pool (`MediaFetchHandoff`), which owns it from
  then on and parks it with the dispatcher for the next keep-alive request.
* **The media pool runs the request again in `admitted` mode**, with
  `rate_limit_admitted` set so `allow()` is not consulted a second time, and
  without taking an ADR-0079 slot: the transport's admission replaces it.
* **Admission.** Before the handoff the transport takes a slot in
  `media_fetch_budget` (an `http::InFlightBudget`, keyed by
  `rate_limit_client_key`): at most `server.http.media_fetch_max_in_flight`
  fetches running or queued (default 64), and at most
  `server.http.media_fetch_max_per_client` for one client (default 8). Over
  either, or if the pool refuses the task, the answer is `429 M_LIMIT_EXCEEDED`
  with `retry_after_ms` 1000, at once. The pool has
  `server.http.media_fetch_threads` workers (default 16) and a queue as deep as
  the global cap, so an admitted handoff is never refused for queue space.
* **Coalescing.** `RemoteMediaFetchCoalescer` allows one fetch per remote file
  (canonical origin and media ID). A second request for a file being fetched
  waits, with the runtime mutex released and within its own deadline, and then
  reads the copy the first one stored. It never displaces that copy.
* **Shutdown.** A handoff that starts after its pool was stopped answers `503`
  without fetching; a handoff whose client has gone is dropped.
* **Unchanged.** Directory lookups (`publicRooms?server=`, remote aliases) keep
  ADR-0079's main-pool budget. A runtime with no media pool (tests, embedded
  callers, `dispatch_local_http_request`) still fetches inline under ADR-0079.
* These settings are configuration, unlike ADR-0079's caps: they size a pool
  that serves only remote media, so raising them cannot take threads from the
  main pool, which was the reason ADR-0079 kept its caps in code.

### Positive Consequences

* A peer that never answers can hold at most the media pool; the main pool and
  every other client request are unaffected.
* A client can show several remote images at once; the first view of a room
  with remote media works.
* A file requested twice at once (an image and its thumbnail) is fetched once.

### Negative Consequences

* Another pool of threads (16 by default) and three more settings.
* Requests that defer run the handler twice. The second run repeats only quick,
  idempotent work (authentication, routing, the cache lookup); the rate limiter
  is told not to count it.
* While the media pool is saturated, remote media is refused with `429` sooner
  than before, because its own budget is now the limit rather than the main
  pool's.
