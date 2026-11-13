// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceRegistry.hpp"
#include "merovingian/auth/FailureWindowTable.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/core/SecretBuffer.hpp"
#include "merovingian/crypto/Ed25519Provider.hpp"
#include "merovingian/database/PersistentPolicyRule.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/SchemaState.hpp"
#include "merovingian/email/SmtpTestResolution.hpp"
#include "merovingian/federation/CachedServerDiscovery.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/EduIdempotenceWindow.hpp"
#include "merovingian/federation/FederationRuntimeState.hpp"
#include "merovingian/federation/RemoteDeviceListCache.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/homeserver/ActiveServerSigningKeySecret.hpp"
#include "merovingian/homeserver/AppserviceDeliveryBackoff.hpp"
#include "merovingian/homeserver/AppserviceEphemeralQueue.hpp"
#include "merovingian/homeserver/AppservicePendingEphemeral.hpp"
#include "merovingian/homeserver/ClientOutboundProxy.hpp"
#include "merovingian/homeserver/ClientOutboundProxyPolicy.hpp"
#include "merovingian/homeserver/InboundTypingUser.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/MediaUploadNotifier.hpp"
#include "merovingian/homeserver/PendingFederatedJoin.hpp"
#include "merovingian/homeserver/RemoteMediaFetchCoalescer.hpp"
#include "merovingian/homeserver/RoomMembers.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/homeserver/RuntimeStartOptions.hpp"
#include "merovingian/homeserver/SendJoinPlanCache.hpp"
#include "merovingian/homeserver/SessionTable.hpp"
#include "merovingian/homeserver/TestOnlyForcedOutboundResolution.hpp"
#include "merovingian/homeserver/TypingExpiry.hpp"
#include "merovingian/http/InFlightBudget.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/identity/TestForcedIdentityResolution.hpp"
#include "merovingian/media/ClamdScanner.hpp"
#include "merovingian/media/LocalMediaRepository.hpp"
#include "merovingian/media/UrlPreviewCache.hpp"
#include "merovingian/net/RuntimeListeners.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/HealthCheckSnapshot.hpp"
#include "merovingian/platform/HardeningSelfCheck.hpp"
#include "merovingian/push/EmailDigestQueue.hpp"
#include "merovingian/push/GatewayCircuitBreaker.hpp"
#include "merovingian/push/GatewayInFlightLimiter.hpp"
#include "merovingian/push/PushBatchAdmission.hpp"
#include "merovingian/push/PushRetryQueue.hpp"
#include "merovingian/push/TestForcedPushGatewayResolution.hpp"
#include "merovingian/sync/SlidingSyncConnectionTable.hpp"
#include "merovingian/sync/SyncNotifier.hpp"
#include "merovingian/trust_safety/PolicyDecision.hpp"
#include "merovingian/trust_safety/PolicyDecisionCache.hpp"
#include "merovingian/trust_safety/PolicyServerHook.hpp"
#include "merovingian/trust_safety/PolicySurface.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace merovingian::auth
{
class Argon2idAdmission;
} // namespace merovingian::auth

namespace merovingian::homeserver
{

constexpr std::size_t room_mutex_stripe_count = 256U;

// Forward declaration — full type in FederationProxy.hpp, included by HomeserverRuntime.cpp.
class FederationProxy;

// The room with `room_id` in `database.rooms` (the first, if two share the ID), or nullptr. One hash lookup on a hit; a
// miss is settled by a scan, so the answer is the same as scanning `rooms` whatever has edited it (ADR-0496). The
// caller holds runtime.mutex: the position index is written from a const lookup.
[[nodiscard]] auto find_local_room(LocalDatabase& database, std::string_view room_id) -> LocalRoom*;
[[nodiscard]] auto find_local_room(LocalDatabase const& database, std::string_view room_id) -> LocalRoom const*;

// Caps on the in-memory ephemeral state a federating peer can create
// (0.12.5 audit, findings 12 and 13).
//
// Both collections are fed straight from federation EDUs: `typing_users` here
// and the receipts in `database.persistent_store.receipts`. `typing_users` only
// ever shrank when a previously-seen user sent typing=false, and receipts are
// upserted but never reaped, so a malicious peer could grow either without
// bound by varying room_id and user_id — monotonic memory growth from remote
// input, ending in an OOM kill.
//
// The primary bound is membership: an EDU for a room this server holds no
// membership row for is dropped, so a peer can only create entries for rooms we
// actually participate in. These caps are the backstop for a peer that is a
// legitimate member of a large room and simply floods it. The oldest typing
// entry is evicted; for receipts the oldest receipt of a remote user is, never
// a local user's, since a local user's receipts are their unread state.
constexpr auto max_inbound_typing_entries = std::size_t{4096U};
constexpr auto max_inbound_receipt_entries = std::size_t{65536U};
// A federated receipt's thread_id is `main` or a thread root's event ID, and an
// event ID is at most 255 bytes (appendices, "Event IDs").
constexpr auto max_receipt_thread_id_bytes = std::size_t{255U};

// Most (user, device) deliveries one inbound m.direct_to_device EDU may queue
// (audit FED-3). Deliveries past this are dropped and logged: a peer that names
// thousands of devices in one EDU must not be able to grow the to-device queue
// without bound. A "*" device counts as one delivery.
constexpr auto max_inbound_direct_to_device_deliveries = std::size_t{1000U};

// What one inbound m.receipt EDU may make this server look at (ADR-0603). A peer chooses the keys of the EDU's
// objects, and each one costs a lookup and, for a joined member, a write under runtime.mutex, so the EDU is read
// only this far, the rest dropped and logged, as m.presence does with max_inbound_presence_entries. The limits
// are generous for real traffic (an EDU names the rooms whose read position moved) and local policy, not
// protocol limits.
constexpr auto max_inbound_receipt_rooms_per_edu = std::size_t{512U};
constexpr auto max_inbound_receipt_users_per_edu = std::size_t{256U};

// What one inbound m.direct_to_device EDU may make this server look at (ADR-0603): the users named under
// `messages`, and the device keys named under all of them. Each is an index lookup; the limits bound the lookups,
// and max_inbound_direct_to_device_deliveries still bounds what is stored.
constexpr auto max_inbound_direct_to_device_users = std::size_t{1024U};
constexpr auto max_inbound_direct_to_device_device_keys = std::size_t{4096U};

// Typing expiry (conformance audit R13, ADR-0199). Spec (PUT /rooms/{roomId}/typing/{userId}):
// "the user is typing for the next N milliseconds where N is the value specified in the timeout
// key". A request without a timeout gets the default; a longer one is cut to the ceiling, so no
// client can make its typing last indefinitely. A federated m.typing EDU carries no timeout, so a
// remote user's typing lasts federation_typing_timeout from the latest EDU that set it.
constexpr auto default_typing_timeout = std::chrono::milliseconds{30'000};
constexpr auto max_typing_timeout = std::chrono::milliseconds{120'000};
constexpr auto federation_typing_timeout = std::chrono::milliseconds{60'000};

// RAII scope guard that wires the active `LocalDatabase` into the
// audit sink on construction and *clears* the install on destruction
// (if the install still belongs to this scope). The full definition
// lives in `merovingian/homeserver/LocalServices.hpp`; the
// forward-declaration here lets `HomeserverRuntime` own one as a
// pimpl-typed member without dragging the audit-sink functions into
// this header. See the class definition for the full contract.
class LocalDatabaseScope;

// FED-11: solicited outbound joins own bounded, transient receipt queues. These
// are never database state. Guard every access with HomeserverRuntime::mutex.
constexpr auto max_pending_join_rooms = std::size_t{32U};
constexpr auto max_pending_join_pdus = std::size_t{32U};
constexpr auto max_pending_join_json_bytes = std::size_t{512U * 1024U};

struct HomeserverRuntime final
{
    HomeserverRuntime();
    HomeserverRuntime(HomeserverRuntime const& other) = delete;
    auto operator=(HomeserverRuntime const& other) -> HomeserverRuntime& = delete;
    HomeserverRuntime(HomeserverRuntime&& other) noexcept;
    auto operator=(HomeserverRuntime&& other) noexcept -> HomeserverRuntime&;
    ~HomeserverRuntime();

    config::Config config{};
    net::RuntimeListeners listeners{};
    LocalDatabase database{};
    // RAII scope guard that binds the audit-sink install to this
    // runtime's lifetime. Constructed in the runtime ctor against
    // `database` and cleared in the dtor; if a different runtime
    // takes over the install (e.g. via move), the source's scope
    // detects the mismatch and becomes a no-op on its own dtor.
    // `std::unique_ptr` keeps the runtime movable without requiring
    // `LocalDatabaseScope` to be a complete type in this header.
    std::unique_ptr<LocalDatabaseScope> audit_sink_scope{};
    federation::FederationRuntimeState federation{};
    media::LocalMediaRepository media_repository{};
    // G15, ADR-0565: the clamd malware scanner, null while security.media.clamd_socket_path is empty. Built once at
    // start-up from the media repository's config; tests install one directly. Its own concurrency bound is atomic,
    // so it is used with `mutex` released (a scan blocks), and held through a unique_ptr because it is not movable.
    std::unique_ptr<media::ClamdScanner> clamd_scanner{};
    platform::HardeningSelfCheck hardening{};
    bool started{false};
    std::unique_ptr<http::OutboundClient> outbound_client{};
    std::function<trust_safety::PolicyServerHook(trust_safety::PolicySurface, std::string_view)>
        trust_safety_policy_server{};
    std::unique_ptr<federation::ServerDiscoveryNetwork> discovery_network{};
    // TTL-bounded cache wrapping `discovery_network`. Non-null in the main
    // process after start_runtime; null in the federation worker and in test
    // harnesses that wire only the raw network. Callers MUST prefer this over
    // `discovery_network` so repeated lookups skip the DNS cascade.
    std::unique_ptr<federation::CachedServerDiscovery> cached_discovery{};
    // Test-only: see TestOnlyForcedOutboundResolution above. Always empty in
    // production; keyed by destination server_name.
    std::map<std::string, TestOnlyForcedOutboundResolution> test_forced_outbound_resolution{};
    // Test-only: a PEM CA bundle the policy-server hook trusts in place of the system store, so a test can
    // stand up a local TLS mock of the policy server (with a `discovery_network` that resolves its host to
    // loopback). Always empty in production.
    std::string test_policy_server_trusted_ca_pem{};
    // Test-only: see identity::TestForcedIdentityResolution. Always empty in
    // production; keyed by identity-server host. Consulted by
    // IdentityServerClient::perform() to pin a local mock IS + in-memory CA
    // bundle in tests (discovery rejects loopback and never sets a CA bundle).
    std::map<std::string, identity::TestForcedIdentityResolution> test_forced_identity_resolution{};
    // Test-only: see push::TestForcedPushGatewayResolution. Always empty in
    // production; keyed by push-gateway host. Consulted by
    // PushGatewayClient::notify() to pin a local mock gateway + in-memory CA
    // bundle in tests (discovery rejects loopback and never sets a CA bundle).
    std::map<std::string, push::TestForcedPushGatewayResolution> test_forced_push_gateway_resolution{};
    // Test-only: when set, the email job connects to these addresses instead of resolving
    // server.email.smtp_url's host, and trusts this PEM instead of the system CA store, so tests
    // can stand up a local mock relay. Always empty in production.
    std::optional<email::SmtpTestResolution> test_forced_smtp_resolution{};
    // Test-only: when set, every event this runtime composes carries this
    // origin_server_ts (Unix ms) instead of the system clock's reading — a
    // clock that stands still, as two requests inside one millisecond see it,
    // or one stepped back. Always empty in production.
    std::optional<std::int64_t> test_frozen_event_clock_ms{};
    // Test-only: called by POST /rooms/{roomId}/upgrade once the replacement room exists and before the
    // tombstone is sent, with runtime.mutex released, so a test can change the old room as a concurrent
    // request would (C21). Always empty in production.
    std::function<void()> test_after_upgrade_room_created{};
    // Application Service API registry (Matrix v1.19). Built once at
    // start_runtime() time from config.appservice().registration_files and
    // never mutated afterward — every request reads it as an immutable,
    // read-only snapshot without locking runtime.mutex. Empty when no
    // registration files are configured, which leaves the entire AS surface
    // inert (see docs/todos/capability-gaps.md, "Application service API").
    appservice::AppserviceRegistry appservices{};
    // Wakes the thread that drains the appservice transaction queues (audit R01). Set by the
    // process entry point once that thread exists; null in tests, which call
    // drain_appservice_queues directly, and in a process with no appservices. Called by
    // enqueue_appservice_delivery with runtime.mutex held, so it must not block or wait for
    // runtime.mutex on another thread (PeriodicJob::wake does neither). Cleared under
    // runtime.mutex at shutdown before the thread is stopped.
    std::function<void()> appservice_delivery_wake{};
    // Wakes the "typing-expiry" job (R13, ADR-0199) so a typing deadline earlier than the job's
    // current sleep is not missed. Set by the process entry point once that thread exists; null
    // in tests, which call expire_typing_notifications directly. Called through
    // wake_typing_expiry with runtime.mutex held, so it must not block or wait for runtime.mutex
    // on another thread (PeriodicJob::wake does neither). Cleared under runtime.mutex at shutdown
    // before the thread is stopped.
    std::function<void()> typing_expiry_wake{};
    // Users whose profile change has rooms left to reach, with the index in database.rooms to
    // resume from (F-11, ADR-0353). No token and no event body: the job sends as the user and reads
    // the profile when it sends. In memory only: a restart leaves those rooms for the next profile
    // change (ADR-0182). Guarded by `mutex`.
    std::map<std::string, std::size_t, std::less<>> profile_propagation_pending{};
    // The user the job served last, so a user with many rooms takes turns with the others. Guarded
    // by `mutex`.
    std::string profile_propagation_last_user{};
    // Wakes the "profile-propagation" job. Set by the process entry point once that thread exists;
    // null in tests, which call propagate_queued_profile directly. Called with runtime.mutex held,
    // so it must not block or wait for runtime.mutex on another thread (PeriodicJob::wake does
    // neither). Cleared under runtime.mutex at shutdown before the thread is stopped.
    std::function<void()> profile_propagation_wake{};
    // The drainer's retry state per appservice, keyed by registration id. In memory only: after
    // a restart the first attempt is immediate. Guarded by `mutex`.
    std::map<std::string, AppserviceDeliveryBackoff, std::less<>> appservice_delivery_backoff{};
    // Ephemeral data queued per appservice, keyed by registration id (R08, ADR-0190). Only
    // appservices with `receive_ephemeral` and a url ever have an entry. Guarded by `mutex`.
    std::map<std::string, AppserviceEphemeralQueue, std::less<>> appservice_ephemeral{};
    // The ephemeral items of the transaction in flight per appservice. Guarded by `mutex`.
    std::map<std::string, AppservicePendingEphemeral, std::less<>> appservice_pending_ephemeral{};
    // Events NOT queued for an appservice because its outbox was at
    // appservice.max_queued_events, since the process started (ADR-0191). Guarded by `mutex`.
    std::map<std::string, std::uint64_t, std::less<>> appservice_outbox_dropped{};
    std::unique_ptr<federation::DispatchWorker> dispatch_worker{};
    // Installed by main when security.federation.enabled is true. Verifies and
    // routes inbound federation, including explicit main-process bypasses.
    // In-process test runtimes may leave it null.
    std::unique_ptr<FederationProxy> federation_proxy{};
    // Test-only: when non-null, every call site that changes this server's
    // residency in a room (create_room, join_room, leave_room) appends
    // room_id here, in addition to (not instead of) notifying
    // federation_proxy. Exercising the real out-of-process worker end to end
    // for every one of those call sites is impractical (see
    // docs/architecture.md, "Federation worker room staleness" — it would
    // require either a live network-reachable remote identity or weakening
    // the federation worker's SSRF policy, neither of which is worth doing
    // just to prove a notification fired). This lets tests instead assert
    // the *design contract* directly and cheaply: every room-residency
    // change must notify the worker, regardless of whether federation_proxy
    // happens to be wired to a real worker in that test. Always nullptr in
    // production; never read except to append to it. Declare the target
    // vector BEFORE the runtime/HomeserverRuntime variable, so it outlives
    // anything the runtime does while it is torn down.
    std::vector<std::string>* test_room_changed_log{nullptr};
    // Test-only (F-43, ADR-0349): stands in for the federation worker's outbound tunnel. When set,
    // perform_outbound_call hands it the signed request of every OutboundAnswerTrust::signature_verified
    // call, in place of federation_proxy, and uses what it returns as the worker's reply. It lets a test
    // play a compromised worker, and count the calls that reach one, without a worker process. An
    // unverified call never reaches it. Always empty in production.
    std::function<http::OutboundResult(http::OutboundRequest const&)> test_worker_outbound_route{};
    // Owned implementation of the runtime signing provider: the production
    // multi-key provider in main, or the refusing provider in the federation
    // worker (RuntimeStartOptions::signing_disabled, ADR-0078).
    std::unique_ptr<crypto::Ed25519Provider> crypto_provider_owned{};
    // Active Ed25519 provider used for server signing. Points at
    // crypto_provider_owned. Check for nullptr before signing.
    crypto::Ed25519Provider* crypto_provider{nullptr};
    // True when this process never signs (RuntimeStartOptions::signing_disabled,
    // the federation worker). The signing secret is not present in this
    // process, so reset_runtime_crypto_provider must leave the refusing
    // provider alone instead of replacing it with one built from local secrets.
    bool crypto_provider_overridden{false};
    sync::SyncNotifier* sync_notifier{nullptr};
    std::vector<InboundTypingUser> typing_users{};
    // Replay window for inbound m.direct_to_device message IDs, keyed on
    // (origin, message_id). In memory only: a restart forgets it (see
    // federation/EduIdempotenceWindow.hpp). Guarded by `mutex` like the state above.
    federation::EduIdempotenceWindow inbound_to_device_window{};
    // Device lists of remote users who share a joined room with a local user (G14, ADR-0560, ADR-0561).
    // Guarded by `mutex`.
    federation::RemoteDeviceListCache remote_device_lists{};
    // Per-room monotonic cursor advanced whenever the set of typing users in
    // the room changes.  Used by /sync and MSC4186 typing extensions to emit
    // the current (possibly empty) typing list on every change.
    std::map<std::string, std::uint64_t> room_typing_stream_id{};
    // The origin_server_ts of the last m.room.create event this runtime
    // composed (Unix ms). Guarded by `mutex`. In room version 12 the room ID
    // is the create event's reference hash, so create_room stamps each create
    // event strictly later than the previous one rather than with the bare
    // clock: two createRoom requests in one millisecond would otherwise derive
    // the same room ID (ADR-0156).
    std::int64_t last_create_event_ts_ms{0};
    // Per-connection MSC4186 sliding sync state.
    // Key: user_id + "/" + device_id + "/" + conn_id (or "__default__").
    sync::SlidingSyncConnectionTable sliding_sync_connections{};
    // In-flight budget and limits for client-triggered outbound proxying (ADR-0079):
    // publicRooms?server=, remote alias lookups and remote media fetches. The
    // budget has its own mutex and is never held together with `mutex`. Held
    // through a unique_ptr so the address slots refer to survives a runtime move.
    std::unique_ptr<http::InFlightBudget> client_outbound_budget{std::make_unique<http::InFlightBudget>()};
    // F-42 (ADR-0361): calls to the external policy server in flight, per surface. Its own budget, apart from
    // client_outbound_budget, so that a flood of one cannot starve the other.
    std::unique_ptr<http::InFlightBudget> policy_server_budget{std::make_unique<http::InFlightBudget>()};
    // ADR-0635: the policy server's decisions about inbound federation origins, and the one request asking about
    // each. Internally locked; behind a pointer so the runtime stays movable.
    std::unique_ptr<trust_safety::PolicyDecisionCache> policy_decision_cache{
        std::make_unique<trust_safety::PolicyDecisionCache>()};
    // ADR-0624: the room-wide part of send_join answers. Has its own mutex, taken with `mutex` held.
    std::unique_ptr<SendJoinPlanCache> send_join_plan_cache{std::make_unique<SendJoinPlanCache>()};
    // ADR-0362: room IDs a createRoom has chosen and not yet stored, so a creation that runs while another waits
    // on the policy server (which releases `mutex`) cannot choose the same one. Guard every access with `mutex`.
    std::set<std::string, std::less<>> rooms_being_created{};
    // True only in a federation worker (ADR-0358): main has already judged the admin's federation policy rule and
    // asked the policy server for every request it forwards, so the worker's own store (no rules on PostgreSQL, a
    // start-up snapshot on SQLite) and its sandbox are not asked to decide it again.
    bool federation_policy_decided_upstream{false};
    ClientOutboundProxyPolicy client_outbound_proxy_policy{default_client_outbound_proxy_policy()};
    // One fetch from the origin per remote media file at a time (ADR-0121). Its
    // mutex is a leaf: never waited on with `mutex` held. Held through a
    // unique_ptr so leads keep a stable address across a runtime move.
    std::unique_ptr<RemoteMediaFetchCoalescer> remote_media_fetch_coalescer{
        std::make_unique<RemoteMediaFetchCoalescer>()};
    // ADR-0212: wakes downloads waiting for a reserved media ID's content. Its
    // mutex is a leaf: never waited on with `mutex` held. Held through a
    // unique_ptr so waiters keep a stable address across a runtime move.
    std::unique_ptr<MediaUploadNotifier> media_upload_notifier{std::make_unique<MediaUploadNotifier>()};
    // ADR-0212: downloads currently waiting for a reserved media ID's content.
    // A wait holds its worker, so at most media_fetch_threads - 1 run at once (none with one worker)
    // (half of those for one user): the media fetch pool always keeps a worker
    // for remote fetches and previews. Its mutex is a leaf, like the budget
    // above. Held through a unique_ptr so slots keep a stable address.
    std::unique_ptr<http::InFlightBudget> pending_upload_waits{std::make_unique<http::InFlightBudget>()};
    // ADR-0213: URL preview responses by canonical URL, bounded by
    // security.media.url_preview_cache_max_entries. Guarded by `mutex`. Not
    // carried across a runtime move: it is only a cache.
    media::UrlPreviewCache url_preview_cache{};
    // Bounded admission semaphore for Argon2id password and registration-token
    // verification (AUTH-4). Stored by unique_ptr so the runtime remains movable
    // while the semaphore itself is not.
    std::unique_ptr<auth::Argon2idAdmission> argon2id_admission{};
    // Failed-login accounting (AUTH-2, AUTH-10). These live on the runtime, not
    // in file-scope statics: a static is shared by every runtime in the process,
    // which in the test binary means lockout state leaks between unrelated
    // scenarios and makes them order-dependent. All three are bounded and
    // guarded by `mutex`. See auth/FailureWindowTable.hpp.
    //   by_source:  password-login failures keyed (account, client source).
    //   by_account: the same failures keyed by account alone, the ceiling that
    //               stops guessing spread over many sources.
    //   uia_device: user-interactive-auth password failures keyed (account,
    //               device). Login failures never touch it and it never feeds
    //               the other two, so a stranger failing logins cannot stop an
    //               authenticated user changing their password.
    auth::FailureWindowTable login_failures_by_source{};
    auth::FailureWindowTable login_failures_by_account{};
    auth::FailureWindowTable uia_failures_by_device{};
    std::uint64_t next_request_sequence{1U};
    // Guards mutable runtime state when requests are handled concurrently.
    // Handlers must release it before outbound network I/O so unrelated
    // requests can continue while a federation round-trip is in flight. Use
    // `RuntimeLockRelease` (RuntimeLockRelease.hpp) to release it — the mutex is
    // recursive, and releasing a single level by hand is what produced the
    // deadlocks in 0.12.1, 0.12.3 and 0.12.6.
    RuntimeMutex mutex{};
    // Established only by the outbound join RAII lease, before releasing mutex.
    // Same-room overlapping joins are refused; startup moves have no leases.
    std::map<std::string, PendingFederatedJoin, std::less<>> pending_federated_joins{};
    // (room_id, user_id) pairs whose membership a federated join, knock or leave
    // is changing with `mutex` released for its network exchange (ADR-0252).
    // Every /join, /knock and /leave for a pair here is refused with 429 until the
    // exchange ends. Guarded by `mutex`.
    std::set<std::pair<std::string, std::string>> membership_exchanges{};
    // R03 (ADR-0165): when each retained federation PDU (store.deferred_pdus,
    // by event_id) may next be retried. In memory only: a row with no entry is
    // due at once, which is what every retained PDU is after a restart.
    // Guarded by `mutex`. Maintained by homeserver::retry_deferred_pdus.
    std::map<std::string, std::chrono::steady_clock::time_point, std::less<>> deferred_pdu_next_attempt{};
    // Asks the deferred-PDU retry job to run now. Set by main after the job
    // starts and cleared, under `mutex`, before it is stopped; null-safe to
    // leave unset (tests, the federation worker). Called with `mutex` held, so
    // it must only wake a thread: PeriodicJob::wake is safe there.
    std::function<void()> deferred_pdu_retry_wake{};
    // Per-room striped mutexes used by inbound PDU ingestion. Each room's events
    // are serialized on their own stripe so per-room ordering is preserved, while
    // events in different rooms can prepare/commit/apply in parallel. The global
    // runtime.mutex is no longer held across database commits.
    std::array<std::mutex, room_mutex_stripe_count> room_stripe_mutexes{};
    // Loser futures from the parallel make_join race (see race_make_join_candidates
    // in RoomService.cpp). When the race finds a winner it returns immediately;
    // the still-running loser tasks (in-flight outbound make_join calls that
    // cannot be cancelled) are moved here so the caller does not block on them.
    // They are drained (removed once ready) at the start of the next race and
    // waited on at runtime destruction. Declared LAST so it is destroyed FIRST:
    // the dtor joins the loser tasks while outbound_client/discovery_network
    // (declared earlier) are still alive, and the tasks' captured `&runtime`
    // reference stays valid throughout the drain. Moves only happen at startup
    // (before any race creates orphans), so the vector is empty at move time.
    std::mutex orphan_futures_mutex_{};
    std::vector<std::future<void>> orphan_futures_{};
    // Count of push-delivery background tasks (dispatch_push_deliveries in
    // RoomService.cpp) currently running. Tracked separately from
    // orphan_futures_.size() because that vector is shared with the
    // make_join race's loser futures (join_room) — sizing the push cap off
    // the shared vector would let a large join race starve push delivery, or
    // let a push burst count against join concurrency.
    //
    // The check-and-increment happens on the dispatcher side under
    // orphan_futures_mutex_ (already held there to reap orphan_futures_), so
    // that read-modify-write against the cap stays correct across concurrent
    // dispatchers. The decrement happens inside the background task itself,
    // as its final action, WITHOUT taking orphan_futures_mutex_: both
    // HomeserverRuntime::~HomeserverRuntime() and test helpers wait on
    // parked futures while holding that same mutex only briefly (to move
    // them out — see the destructor), never across the blocking wait, but a
    // task that needed the mutex to finish would still deadlock against any
    // waiter that held it for the wait itself. std::atomic sidesteps the
    // question entirely: the task never needs the mutex to complete. See
    // at_background_task_capacity() and k_max_in_flight_push_deliveries in
    // RoomService.cpp.
    std::atomic<std::size_t> push_delivery_in_flight_{0U};
    // Password-reset emails being sent (send_password_reset_email, ADR-0481), counted apart from
    // orphan_futures_ so unrelated background tasks (make_join race losers, push deliveries) cannot use up the
    // reset sends. Incremented under runtime.mutex before a task starts; the task's permit decrements it on every
    // exit path.
    std::atomic<std::size_t> password_reset_sends_in_flight_{0U};
    // Dispatcher-side lookup/admission/reaping is guarded by
    // orphan_futures_mutex_. Tasks retain a shared atomic counter and release
    // it without any completion-time lock. Zero entries are swept on dispatch;
    // retained user entries are bounded by the global delivery budget.
    // Runtime moves remain startup-only, like the captured-runtime futures.
    std::unordered_map<std::string, std::shared_ptr<std::atomic<std::size_t>>> // SHARED_PTR: reviewed - task lifetime.
        push_delivery_in_flight_by_user_{};
    // OUT-3, ADR-0151: skips a push gateway host that keeps failing. Internally
    // locked; shared by every delivery task. Behind a pointer so the runtime
    // stays movable (its mutex is not).
    std::unique_ptr<push::GatewayCircuitBreaker> push_gateway_breaker_{std::make_unique<push::GatewayCircuitBreaker>()};
    // F-79, ADR-0409: requests in flight to each push gateway host and resolved address, capped so
    // many subdomains of one server cannot hold the delivery budget. Internally locked; shared by
    // the delivery tasks and the retry job. Behind a pointer so the runtime stays movable.
    std::unique_ptr<push::GatewayInFlightLimiter> push_gateway_in_flight_{
        std::make_unique<push::GatewayInFlightLimiter>()};
    // ADR-0634: gateway hosts carrying recipient batches, so one host cannot hold the delivery budget. Internally
    // locked; consulted by dispatch_push_deliveries. Behind a pointer so the runtime stays movable.
    std::unique_ptr<push::PushBatchAdmission> push_batch_admission_{std::make_unique<push::PushBatchAdmission>()};
    // R14, ADR-0206: notifications waiting to be sent again after a failed attempt. Internally
    // locked; delivery tasks fill it and the push retry job (main.cpp) drains it through
    // retry_due_push_deliveries. In memory only: a restart forgets pending retries. Behind a
    // pointer so the runtime stays movable.
    std::unique_ptr<push::PushRetryQueue> push_retry_queue_{std::make_unique<push::PushRetryQueue>()};
    // ADR-0219: kind "email" pushers with a notification email due, and when each last sent one.
    // Internally locked; push delivery notes notifications (under runtime.mutex) and the email job
    // (main.cpp) sends through send_due_email_notifications. In memory only. Behind a pointer so the
    // runtime stays movable.
    std::unique_ptr<push::EmailDigestQueue> email_digest_queue_{std::make_unique<push::EmailDigestQueue>()};
};

// Removes every already-completed future from `futures` in place, preserving
// the relative order of the survivors. Readiness is checked with a
// non-blocking wait_for(0s) — never .get()/.wait() on a future that might
// still be running. Shared by every call site that parks background work in
// HomeserverRuntime::orphan_futures_ (join_room's make_join race losers,
// dispatch_push_deliveries's push-gateway tasks) so the reap-before-park
// policy is defined exactly once. Callers are responsible for holding
// orphan_futures_mutex_ while calling this.
auto reap_completed_futures(std::vector<std::future<void>>& futures) -> void;

// Pure capacity check for a background task pool bounded by a fixed cap —
// no futures, no threads, no I/O — so the cap boundary (drop the N+1th unit
// of work rather than spawn it) can be exercised directly in a unit test
// without any concurrency machinery. `in_flight_count` is the count AFTER
// reaping.
[[nodiscard]] constexpr auto at_background_task_capacity(std::size_t in_flight_count, std::size_t cap) noexcept -> bool
{
    return in_flight_count >= cap;
}

// Typing-state helpers used by client-server and federation handlers.
[[nodiscard]] auto current_typing_users_in_room(HomeserverRuntime const& rt, std::string_view room_id)
    -> std::vector<std::string>;
[[nodiscard]] auto room_typing_stream_id_for(HomeserverRuntime const& rt, std::string_view room_id) -> std::uint64_t;
[[nodiscard]] auto update_room_typing_stream_id_if_changed(HomeserverRuntime& rt, std::string_view room_id,
                                                           std::vector<std::string> const& previous) -> std::uint64_t;
// Removes every typing entry whose expiry is at or before `now`, and advances the typing stream
// position of each room whose typing users changed, so /sync and sliding sync report the room's
// new (possibly empty) m.typing list (R13, ADR-0199). The caller holds runtime.mutex, wakes
// sync waiters when `changed`, and tells remote servers about `expired_local`.
[[nodiscard]] auto expire_typing(HomeserverRuntime& rt, std::chrono::steady_clock::time_point now) -> TypingExpiry;
// Wakes the typing-expiry job, if one runs. Every path that sets a user typing calls it, with
// runtime.mutex held, after setting `expires_at` (R13, ADR-0199).
auto wake_typing_expiry(HomeserverRuntime& rt) -> void;

[[nodiscard]] auto bootstrap_local_database(config::Config const& config) -> LocalDatabase;
// `fill_store`, when set, fills the opened store before hydration (RuntimeStartOptions::fill_store, ADR-0733); a
// false result returns the database unopened.
[[nodiscard]] auto bootstrap_local_database(config::Config const& config, database::SchemaState existing_state,
                                            database::TableLoadProfile profile = database::TableLoadProfile::full,
                                            std::function<bool(database::PersistentStore&)> const& fill_store = {})
    -> LocalDatabase;
[[nodiscard]] auto database_has_table(LocalDatabase const& database, std::string_view table_name) noexcept -> bool;
// Allocates the next timeline stream_ordering and persists the new
// high-water mark to the event_stream_watermark singleton. Every
// stream_ordering allocation must flow through this helper: some
// allocations (membership stream positions) are not backed by a persisted
// event row, so a counter rebuilt from events alone regresses across
// restarts and invalidates every pos/since token clients still hold.
[[nodiscard]] auto allocate_stream_ordering(LocalDatabase& database) -> std::uint64_t;
// Allocates `count` consecutive orderings and persists the high-water mark once,
// for a caller that stores that many events in one transaction. Returns the
// first; the caller may leave some unused.
[[nodiscard]] auto allocate_stream_orderings(LocalDatabase& database, std::size_t count) -> std::uint64_t;

// The newest event stream position a sync token, a long-poll check or a
// sliding-sync pos may name: just below the oldest pending ordering, or the
// newest allocated one when none is pending. Read with runtime.mutex held.
[[nodiscard]] auto visible_stream_position(LocalDatabase const& database) noexcept -> std::uint64_t;
// The accounts on this server, as a set, so a roster of any size is classified in one pass.
[[nodiscard]] auto local_user_ids(LocalDatabase const& database) -> std::unordered_set<std::string_view>;
struct RuntimeStartResult;

[[nodiscard]] auto start_runtime(config::Config const& config) -> RuntimeStartResult;
[[nodiscard]] auto start_runtime(config::Config const& config, database::SchemaState existing_state)
    -> RuntimeStartResult;
[[nodiscard]] auto start_runtime(RuntimeStartOptions opts) -> RuntimeStartResult;
// Loads and decrypts every currently-active server signing secret from the
// persistent store. Secrets are sorted with the preferred key first.
[[nodiscard]] auto active_server_signing_key_secrets(HomeserverRuntime& runtime)
    -> std::vector<ActiveServerSigningKeySecret>;

// Re-creates the runtime's owned signing provider from all currently-active
// signing secrets. Called by start_runtime after the signing key is ensured
// and by rotate_server_signing_key after a rotation. This is a no-op when an
// external provider override is active.
auto reset_runtime_crypto_provider(HomeserverRuntime& runtime) -> void;
[[nodiscard]] auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot;
[[nodiscard]] auto admin_health_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_metrics_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_audit_summary(HomeserverRuntime const& runtime,
                                       std::optional<observability::AuditCategory> category = std::nullopt,
                                       std::optional<std::string_view> event_type = std::nullopt) -> std::string;
[[nodiscard]] auto find_policy_rule(HomeserverRuntime const& runtime, std::string_view scope, std::string_view entity)
    -> std::optional<database::PersistentPolicyRule>;
[[nodiscard]] auto resolve_policy_server_hook(HomeserverRuntime& runtime, trust_safety::PolicySurface surface,
                                              std::string_view entity) -> trust_safety::PolicyServerHook;
// F-21 (ADR-0358): the decision on a verified inbound federation request from `origin`: the admin's
// scope-"federation" policy rule (read under runtime.mutex) and, when `consult_policy_server` is set, the
// external policy server (a network call, made with the mutex released). Main applies the rule in
// FederationProxy::handle before any branch, and asks the policy server where the request is handed on: in the
// proxy for a worker, in handle_federation_http_request for what main answers itself. The main-side relay
// handlers pass false, since a relayed PDU is not a request worth a round trip to the policy server of its own.
[[nodiscard]] auto evaluate_inbound_federation_policy(HomeserverRuntime& runtime, std::string_view origin,
                                                      bool consult_policy_server) -> trust_safety::PolicyDecision;
auto apply_runtime_membership(LocalDatabase& database, std::string_view room_id, std::string_view user_id,
                              std::string_view membership) -> void;

} // namespace merovingian::homeserver
