// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

struct CreateRoomOptions final
{
    std::string room_version{"12"};
    canonicaljson::Object creation_content{};
    canonicaljson::Object power_level_content_override{};
    std::vector<canonicaljson::Value> initial_state{};
    std::vector<std::string> trusted_invitees{};
    std::string preset{"private_chat"};
    std::string name{};
    std::string topic{};
    std::string room_alias_name{};
    std::vector<std::string> invitees{};
    bool is_direct{false};
    bool directory_public{false};
};

struct ValidatedMakeJoinResponse final
{
    bool ok{false};
    std::string reason{};
    std::string room_version{};
    canonicaljson::Object event{};
};

struct ValidatedMakeLeaveResponse final
{
    bool ok{false};
    std::string reason{};
    std::string room_version{};
    canonicaljson::Object event{};
};

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token,
                               CreateRoomOptions const& options) -> OperationResult;
// Joins a room. `via_servers` are candidate resident servers (from the join
// endpoint's `server_name`/`via` query parameters) to attempt federation
// make_join/send_join against. They are required to join a remote room version 12
// room, whose room ID is a bare reference hash with no `:server` suffix (MSC4291)
// and therefore cannot be routed from the room ID alone.
[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                             std::vector<std::string> const& via_servers = {},
                             canonicaljson::Object const* third_party_signed = nullptr) -> OperationResult;
[[nodiscard]] auto leave_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult;
[[nodiscard]] auto invite_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                               std::string_view target_user_id, std::string_view reason = {}) -> OperationResult;
// Creates a local-only third-party identifier invite. Generates a random token
// and an Ed25519 keypair, then composes and persists an
// `m.room.third_party_invite` state event whose `state_key` is the token and
// whose content carries the generated public key. The matching private key is
// held in memory only long enough to generate the keypair; callers that need
// to validate a `third_party_signed` join later must look up the public key
// from the persisted event.
[[nodiscard]] auto invite_user_by_threepid(HomeserverRuntime& runtime, std::string_view access_token,
                                           std::string_view room_id, std::string_view id_server,
                                           std::string_view medium, std::string_view address,
                                           std::string_view id_access_token) -> OperationResult;
[[nodiscard]] auto ban_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                            std::string_view target_user_id, std::string_view reason = {}) -> OperationResult;
[[nodiscard]] auto kick_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                             std::string_view target_user_id, std::string_view reason = {}) -> OperationResult;
[[nodiscard]] auto unban_user(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view target_user_id) -> OperationResult;
[[nodiscard]] auto forget_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult;
// Knocks on a room. When this server is in the room, the knock is composed here;
// otherwise it goes through make_knock and send_knock to the first of
// `via_servers` (routed as a join is, ADR-0242) that offers a template, and the
// resident's verified knock_room_state is kept for the user's /sync (ADR-0243).
// `reason`, when not empty, is the knock event's content.reason. A resident that
// refuses with 403 is a 403; no server to ask, or an unknown local room, is a 404.
[[nodiscard]] auto knock_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::vector<std::string> const& via_servers = {}, std::string_view reason = {})
    -> OperationResult;
// Parses the `server_name=` and `via=` query parameters (each may repeat) from a
// raw query string into an ordered, de-duplicated list of server names. Values are
// percent-decoded once. nullopt rejects NUL in recognized values; unrelated
// parameters remain untouched. `server_name` is legacy; `via` (MSC4156) is current.
[[nodiscard]] auto parse_join_via_servers(std::string_view query) -> std::optional<std::vector<std::string>>;
// Builds the ordered list of candidate resident servers to attempt make_join /
// Single choke point for the "room_id changed here" signal to the out-of-process
// federation worker, which answers make_join, make_leave, state and backfill
// requests from its own snapshot of the room. Every path that creates a room,
// changes a membership in it (locally, or by accepting a send_join, send_leave or
// send_knock) or stores a relayed event MUST call this, or that snapshot goes stale
// (see docs/architecture.md, "Federation worker room staleness"). Tests pin the
// contract through HomeserverRuntime::test_room_changed_log without a real worker.
auto notify_room_changed(HomeserverRuntime& runtime, std::string_view room_id) -> void;

// Sends the membership event this server, as the resident, just accepted from
// `requesting_server` through send_join, send_leave or send_knock to the room's other
// servers: those of its joined members once the event applies, never this server and never
// `requesting_server`, which already holds it. Server-Server API, "Joining Rooms": "The
// resident server must also send the event to other servers participating in the room";
// "Leaving Rooms (Rejecting Invites)": "The resident server will then send the event to
// other servers in the room". `event_json` is the stored copy (redacted after a hash
// mismatch, carrying this server's signature after authorising a restricted join), not
// the request body. Call with `runtime.mutex` held, after the roster reflects the event.
auto federate_accepted_membership_event(HomeserverRuntime& runtime, std::string_view room_id, std::string_view event_id,
                                        std::string const& event_json, std::string_view requesting_server) -> void;

// Applies a stored membership change to the live roster and records the device-list changes it causes
// (spec "Tracking the device list for a user": a user who starts sharing a room with a local user is
// `changed`, one who stops sharing any is `left`). Every path that learns a membership, local or over
// federation (send_join, send_leave, PDUs in a transaction), goes through this and never edits
// `LocalRoom::members` itself. The roster is updated even when recording a device-list change fails;
// the result is false in that case.
[[nodiscard]] auto apply_membership_to_roster(HomeserverRuntime& runtime, std::string_view room_id,
                                              std::string_view user_id, std::string_view membership) -> bool;

// send_join against. When the client names via servers, only those, in request
// order: room IDs "are not routable on their own" (appendices, Room IDs), so the
// room ID's domain never overrides the client's choice (ADR-0242). With no via
// servers, the room ID's domain when it has one (room versions < 12); a version 12
// room ID is a bare hash, so it then has no candidate at all. Our own server and
// duplicates are removed.
[[nodiscard]] auto join_candidate_servers(std::vector<std::string> const& via_servers, std::string_view room_id,
                                          std::string_view our_server) -> std::vector<std::string>;
// Truncates an ordered candidate list to at most `max_candidates` entries, preserving
// order — via lists are recommended to be ordered by likelihood of being resident, so
// the first entries are kept. Guards against an unbounded via list spawning an
// unbounded number of make_join probe threads. `max_candidates == 0` is clamped to 1.
[[nodiscard]] auto cap_join_candidates(std::vector<std::string> candidates, std::uint32_t max_candidates)
    -> std::vector<std::string>;
[[nodiscard]] auto validate_make_join_response(std::string_view requested_room_id, std::string_view requested_user_id,
                                               std::string_view body) -> ValidatedMakeJoinResponse;
// Server-Server API, "Joining Rooms": the joining server "is expected to add or
// replace the origin, origin_server_ts, and event_id on the templated event
// received by the resident server". Puts this server's name and clock on a
// validated make_join or make_leave template before it is hashed and signed, and
// drops any event_id (room versions 3 and later derive it from the event). The
// resident never chooses the timestamp this server signs.
auto claim_membership_event_template(canonicaljson::Object& event, std::string_view our_server_name,
                                     std::int64_t now_ms) -> void;
[[nodiscard]] auto validate_make_leave_response(std::string_view requested_room_id, std::string_view requested_user_id,
                                                std::string_view body) -> ValidatedMakeLeaveResponse;
// Synchronous outbound federation call — signs in-process then routes via
// federation proxy (worker thread pool) if available, else direct outbound client.
// Returns {true, body} on HTTP 2xx, {false, reason} otherwise.
// room_id is used only for worker shard routing; pass {} for non-room requests.
// `secret_key` is an owned 64-byte Ed25519 secret key in a mlocked
// core::SecretBuffer. Callers copy it from runtime.database.signing_secret_key
// while holding runtime.mutex and std::move it in; the call may release the
// mutex during the network round trip and must not dangle on the runtime buffer.
// `max_response_bytes` overrides the outbound response body cap (0 = use the
// OutboundCall default of 16 MiB); send_join passes
// runtime.federation.config.join_response_max_bytes since a large room's
// full state routinely exceeds the default.
[[nodiscard]] auto perform_sync_outbound_call(HomeserverRuntime& runtime, std::string_view room_id,
                                              federation::OutboundTransaction const& transaction,
                                              std::string_view key_id, core::SecretBuffer secret_key,
                                              std::string_view diagnostic_event, std::uint32_t timeout_seconds,
                                              std::uint64_t max_response_bytes = 0U) -> std::pair<bool, std::string>;
// perform_sync_outbound_call for calls a client can trigger without
// authentication (publicRooms?server=, a remote alias lookup): `deadline_seconds`
// is a total wall-clock budget for server discovery plus the request, not a
// per-step timeout, and the federation-worker round trip may exceed it by at
// most runtime.client_outbound_proxy_policy.worker_margin_seconds instead of the
// usual 10 s. A budget already used up is reported as "deadline exceeded" without
// touching the network. Callers hold a client-outbound budget slot around it
// (ADR-0079, `admit_client_outbound_proxy`).
[[nodiscard]] auto perform_bounded_outbound_call(HomeserverRuntime& runtime, std::string_view room_id,
                                                 federation::OutboundTransaction const& transaction,
                                                 std::string_view key_id, core::SecretBuffer secret_key,
                                                 std::string_view diagnostic_event, std::uint32_t deadline_seconds)
    -> std::pair<bool, std::string>;

// The limits of a bounded call: one wall-clock deadline for discovery plus the
// request, and the margin the federation-worker round trip may add to it.
struct BoundedOutboundLimits final
{
    OutboundDeadline deadline;
    std::chrono::seconds worker_margin;
};

// What one outbound federation call came to. `body` is the response body on
// success and a reason otherwise; `remote_status` is the HTTP status the remote
// server answered with, or 0 when no answer arrived (discovery, transport or
// signing failure, deadline).
struct OutboundCallResult final
{
    bool ok{false};
    std::string body{};
    std::uint16_t remote_status{0U};
};

// The shared implementation of perform_sync_outbound_call (bounded == nullopt)
// and perform_bounded_outbound_call. Call it directly only when the remote's
// status decides the answer, as a membership call refused with 403 does.
[[nodiscard]] auto perform_outbound_call(HomeserverRuntime& runtime, std::string_view room_id,
                                         federation::OutboundTransaction const& transaction, std::string_view key_id,
                                         core::SecretBuffer secret_key, std::string_view diagnostic_event,
                                         std::uint32_t timeout_seconds, std::uint64_t max_response_bytes,
                                         std::optional<BoundedOutboundLimits> const& bounded) -> OutboundCallResult;

// ADR-0064 phase B1: joined_members is what callers used before (the user
// IDs found with membership="join" among the ingested state entries);
// state_entries is the full (event_type, state_key) -> event_id map of
// every state event ingested — the room's state immediately BEFORE the
// join event, used by join_room to seed a snapshot state group — with each
// key once, since a state group holds a key at most once.
// recorded_state_events counts every state event of the array that is now
// stored, a repeat included: join_room compares it with the verified array
// to tell a complete snapshot from a failed one.
struct SendJoinStateIngestResult final
{
    std::vector<std::string> joined_members{};
    std::vector<database::PersistentStateGroupStateEntry> state_entries{};
    std::size_t recorded_state_events{0U};
};

// Ingests the `state` array from a send_join response for `room_id`, the room
// being joined. Every event is stored in the persistent event graph, with
// status "outlier" (ADR-0064): these events are not (yet) reachable by walking
// prev_events from anything we hold, so they get no state group or forward
// extremity of their own — see join_room, which builds one snapshot state
// group from the returned state_entries instead. State events — identified by
// the PRESENCE of the "state_key" field in the raw JSON, even when its value
// is "" — are also written to the state table. This is the correct
// discriminator: the Matrix spec defines any event with a "state_key" field as
// a state event, regardless of whether that value is empty.
//
// FED-1 (ADR-0083): an entry that does not belong to `room_id` (see
// filter_send_join_events_for_room) is skipped — never stored, never written
// to current_state, never counted as a member. join_room filters the arrays
// before verification as well; this is the last line, at the writer.
[[nodiscard]] auto ingest_send_join_state(HomeserverRuntime& runtime, std::string_view room_id,
                                          canonicaljson::Array const& state_arr, rooms::RoomVersionPolicy const& policy)
    -> SendJoinStateIngestResult;
// FED-1 (ADR-0083): returns the entries of a send_join response's `state` or
// `auth_chain` array that belong to `room_id`, the room being joined, dropping
// every other entry. An event belongs to the room when its `room_id` equals
// `room_id`. Under a room version whose m.room.create event defines the room ID
// (v12, rooms/v12.md), the create event has no `room_id`: it belongs when
// "!" + its reference-hash event ID (sigil swapped) equals `room_id`, and a
// create event that carries a `room_id` is dropped (v12 auth rule 1.2 rejects
// it). An entry with no determinable room is dropped.
[[nodiscard]] auto filter_send_join_events_for_room(canonicaljson::Array const& events, std::string_view room_id,
                                                    rooms::RoomVersionPolicy const& policy) -> canonicaljson::Array;
// Filters a send_join response's `state` or `auth_chain` array down to the
// events whose Ed25519 signature verifies against their sender domain's
// signing key. A large room's state array carries one m.room.member per
// member — thousands of distinct sender home servers for a large room — so
// distinct (sender_domain, key_id) pairs are resolved via
// runtime.federation.remote_key_resolver with concurrent fan-out capped at
// `security.federation.join_state_key_parallelism` (default 100) rather than
// serially.
//
// An event whose sender domain is `our_server` is verified like any other
// (FED-1, ADR-0083), but against this server's OWN signing keys — the current
// key and every retired key the server still holds, read from the persisted
// server_signing_keys rows it generated — never fetched over the network. An
// own-domain event signed under a key ID we do not hold is dropped.
// Fail-closed (src/federation/AGENTS.md rule 2): an event whose key cannot be
// found, or whose signature does not verify, is silently dropped from the
// returned array rather than persisted or failing the join. Safe to call with
// runtime.mutex released: the only runtime state read is the signing-key
// snapshot, which takes its own lock.
[[nodiscard]] auto filter_verified_send_join_events(HomeserverRuntime& runtime, canonicaljson::Array const& events,
                                                    rooms::RoomVersionPolicy const& policy, std::string_view our_server)
    -> canonicaljson::Array;

[[nodiscard]] auto ensure_runtime_server_signing_key(HomeserverRuntime& runtime)
    -> std::optional<database::PersistentServerSigningKey>;
// Returns every currently-active signing-key record for this server without
// loading secrets. The vector is sorted with the preferred key (greatest
// valid_until_ts) first, and is used to publish the server's verify_keys.
[[nodiscard]] auto collect_active_server_signing_keys(HomeserverRuntime const& runtime)
    -> std::vector<database::PersistentServerSigningKey>;
// Returns the preferred active server signing-key record (key_id and public_key)
// without loading or decrypting the secret. Used by federation paths that sign
// through an external provider (e.g. the out-of-process worker) where the secret
// must not enter the runtime.
[[nodiscard]] auto find_active_server_signing_key(HomeserverRuntime const& runtime)
    -> std::optional<database::PersistentServerSigningKey>;
[[nodiscard]] auto publish_server_signing_keys(HomeserverRuntime& runtime) -> OperationResult;
// Rotates this server's Ed25519 signing key. The currently active key is retired
// (its valid_until_ts is set to "now" so it is published under old_verify_keys) and
// a freshly generated key becomes active. Federation peers continue to verify events
// signed under the retired key via old_verify_keys until it expires from their cache.
// Refreshes the cached /_matrix/key/v2/server response. On success the result value
// carries the new active key_id.
[[nodiscard]] auto rotate_server_signing_key(HomeserverRuntime& runtime) -> OperationResult;
[[nodiscard]] auto send_event(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view event_json) -> OperationResult;
// Spec (Client-Server API, "Events on Change of Profile Information"): when a user changes their
// display name or avatar URL, "an m.room.member event (with a join membership) is sent to every
// room the user is a member of, to update the displayname and avatar_url". Sends that event,
// carrying the user's current profile, through send_event to each room whose current m.room.member
// state for `access_token`'s user is a join that does not already carry it. A room the runtime
// member list names but whose state does not hold the user as joined is skipped, never joined
// (ADR-0182). A room that refuses the event (its auth rules, room version, size limits or a storage
// failure) is logged as a warning; the others still get theirs. Then sends the section's
// m.presence update: the user's current presence (offline if
// never set) is stored again at a new sync stream position, and /sync adds the display name and
// avatar URL to it. Called after the profile is stored, so it succeeds whatever the rooms and
// presence do: only an unauthenticated token fails it (401). A room left behind is sent the next
// profile update, without duplicate membership events to rooms already current. Takes
// runtime.mutex (recursive).
[[nodiscard]] auto propagate_profile_change(HomeserverRuntime& runtime, std::string_view access_token)
    -> OperationResult;
// Evaluates push rules and dispatches push notifications (and GET
// /notifications history rows) for `envelope`, an event that was just
// accepted through federation ingestion (ingest_pdu_event) rather than
// composed locally via send_event. PDUs accepted over federation never pass
// through send_event, so without this call the push pipeline never runs for
// them at all — a remote room member's message would produce no
// /notifications row and no Push Gateway request for a local recipient (the
// normal federated-room case). Mirrors send_event's own build_pending_push_
// deliveries/dispatch_push_deliveries call. `accepted_stream_ordering` is the
// value ingest_pdu_event assigned the event (PduIngestionResult::
// accepted_stream_ordering), needed for GET /notifications pagination.
// Callers must invoke this only once per accepted PDU — see
// wire_federation_callbacks_impl's pdu_sink, the sole call site, for why that
// holds structurally. Safe to call under runtime.mutex; the actual Push
// Gateway network calls still happen off the request path (see
// dispatch_push_deliveries).
auto deliver_federation_push_notifications(HomeserverRuntime& runtime, federation::InboundPduEnvelope const& envelope,
                                           std::uint64_t accepted_stream_ordering) -> void;
[[nodiscard]] auto fetch_room_state(HomeserverRuntime const& runtime, std::string_view access_token,
                                    std::string_view room_id) -> OperationResult;
// Converts a stored persistent event into a client-facing event value,
// injecting server-generated fields: event_id and, for state events,
// unsigned.replaces_state (Matrix v1.19). Used by every client-event path
// (/sync, /messages, /rooms/{roomId}/state, etc.) so the emitted shape is
// consistent.
[[nodiscard]] auto client_event_with_id(database::PersistentStore const& store, database::PersistentEvent const& event)
    -> canonicaljson::Value;

struct FetchRelationsRequest final
{
    std::string room_id{};
    std::string event_id{};
    std::optional<std::string> rel_type{};
    std::optional<std::string> event_type{};
    std::optional<std::string> dir{};
    std::optional<std::string> from{};
    std::optional<std::uint64_t> limit{};
    std::optional<bool> recurse{};
    std::optional<std::string> to{};
};

// Retrieve child events that relate to a given parent event, optionally
// filtered by rel_type and event_type. Implements the three GET
// /_matrix/client/v1/rooms/{roomId}/relations/... endpoints from Matrix v1.19.
[[nodiscard]] auto fetch_relations(HomeserverRuntime const& runtime, std::string_view access_token,
                                   FetchRelationsRequest const& request) -> OperationResult;

struct FetchThreadsRequest final
{
    std::string room_id{};
    // "all" (default) or "participated". Any other value is rejected with 400
    // rather than silently treated as "all".
    std::optional<std::string> include{};
    std::optional<std::string> from{};
    std::optional<std::uint64_t> limit{};
};

// Lists the thread roots in a room, most recently active first, each carrying its
// bundled `m.thread` aggregation (latest_event / count / current_user_participated).
// Implements GET /_matrix/client/v1/rooms/{roomId}/threads from Matrix v1.19
// ("Querying threads in a room"). Events from users the caller ignores are excluded
// from the aggregation, and a root sent by an ignored user is returned redacted.
[[nodiscard]] auto fetch_room_threads(HomeserverRuntime const& runtime, std::string_view access_token,
                                      FetchThreadsRequest const& request) -> OperationResult;

[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t;

} // namespace merovingian::homeserver
