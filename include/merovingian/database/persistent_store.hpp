// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/migration.hpp"
#include "merovingian/database/statement.hpp"
#include "merovingian/events/event.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::database
{

enum class PersistentStoreBackend
{
    memory,
    postgresql,
    sqlite,
};

// ADR-0062 part 2 (0.12.13 audit, finding N1): which tables a store open
// hydrates into memory. `full` is every process except the federation
// worker. `federation_worker` hydrates ONLY the tables
// federation_worker_table_allowlist names below — a fail-closed allowlist,
// not a denylist, so a worker connecting with a least-privilege PostgreSQL
// role (granted SELECT on exactly those tables) can still start, and a
// worker connecting with ANY role never holds unlisted material resident
// regardless of backend. Only open_postgresql_persistent_store honours this
// today — see docs/database-persistence.md, "Federation worker
// least-privilege role", for why the SQLite loader was left unchanged.
enum class TableLoadProfile
{
    full,
    federation_worker,
};

// The exact, minimal set of tables TableLoadProfile::federation_worker
// allows a store open to hydrate. This is an ALLOWLIST, not a denylist: a
// table absent from this array is excluded by default, so a future
// migration's new table is unreadable by the worker until someone adds it
// here deliberately (fail closed on the unknown, per the 0.12.13 audit N1
// part-2 review).
//
// Each entry was derived by tracing every FederationRuntimeState callback
// NOT overridden by WorkerEventLoop::run() (see
// src/federation_worker/worker_event_loop.cpp and
// src/federation_worker/AGENTS.md rule 3 for the overridden/relayed set —
// pdu_sink, membership_acceptor, invite_handler, edu_sink,
// one_time_keys_claim_provider, user_devices_provider,
// device_keys_query_provider, profile_query_provider, event_query_provider —
// whose DEFAULT local implementations are therefore never reached inside the
// worker process) to the PersistentStore fields it actually reads:
//
//   rooms               membership_template_provider (make_join/leave/knock),
//                       directory_query_provider, space_hierarchy_provider —
//                       local_http_router.cpp:1278, :1749, space_hierarchy.cpp
//   membership          directory_query_provider (joined servers for a room
//                       alias), space_hierarchy.cpp's joined_member_count —
//                       local_http_router.cpp:1749
//   current_state       membership_template_provider (auth_events),
//                       room_version_resolver, room_server_acl_provider,
//                       space_hierarchy.cpp (join_rule/is_space/space_children)
//                       — local_http_router.cpp:1335, :1830, :1838
//   events              membership_template_provider (forward extremities),
//                       build_backfill_pdus, build_state_response,
//                       build_state_ids_response,
//                       build_get_missing_events_response —
//                       local_http_router.cpp:1354, federation/event_query.cpp
//   event_edges         reconstruct_event_relations populates
//                       PersistentEvent::prev_event_ids from this table;
//                       without it every event's prev_events reads back
//                       empty for the make_join/backfill/missing_events
//                       routes above — database/persistent_store.cpp
//                       reconstruct_event_relations
//   event_auth          same reconstruct_event_relations dependency, for
//                       PersistentEvent::auth_event_ids (auth-chain walks in
//                       build_state_response/build_state_ids_response)
//   event_signatures    same reconstruct_event_relations dependency, for
//                       PersistentEvent::signatures
//   room_aliases        directory_query_provider (find_room_alias) —
//                       local_http_router.cpp:1736
//   server_signing_keys remote_key_cache_probe / remote_key_resolver cache
//                       OTHER servers' keys here (find_cached_remote_key /
//                       store_server_signing_key) — local_http_router.cpp:
//                       1857-1871, federation/remote_key_cache.cpp. Column-
//                       restricted: the worker load path (see
//                       postgresql_store.cpp load_persistent_rows) never
//                       selects the secret_key column, and
//                       provision-federation-worker-role.sql grants SELECT
//                       on exactly the other four columns — so this entry
//                       never exposes this server's own signing secret even
//                       though the table name is shared with it.
//
//   state_groups        Phase A (ADR-0064) plumbing: the worker serves
//                       federation /state and /state_ids locally today from
//                       current_state/event relations, and a later phase
//                       moves that to state groups. Readable now so that
//                       phase does not require a further grant change.
//   state_group_state   same ADR-0064 phase-A reasoning, for a group's own
//                       delta/snapshot rows.
//   event_state_groups  same ADR-0064 phase-A reasoning, for the
//                       event -> state group mapping.
//   forward_extremities same ADR-0064 phase-A reasoning: the worker's
//                       membership_template_provider already reads forward
//                       extremities via `events` (see above); this table
//                       becomes the maintained source of truth for that.
//
// Every other table PersistentStore can hold — including the operator's own
// server_signing_keys.secret_key column, users/access_tokens/refresh_tokens/
// login_tokens/openid_tokens/account_threepids and every other credential or
// per-user table — is either relayed to main over IPC when the worker
// genuinely needs it, or never read by the worker at all. See
// docs/database-persistence.md, "Federation worker least-privilege role",
// for the full classification of every table migrations/*.sql creates
// (cross-checked against this array by
// tests/unit/test_worker_db_uri.cpp).
inline constexpr std::array<std::string_view, 13> federation_worker_table_allowlist{
    "rooms",
    "membership",
    "current_state",
    "events",
    "event_edges",
    "event_auth",
    "event_signatures",
    "room_aliases",
    "server_signing_keys",
    "state_groups",
    "state_group_state",
    "event_state_groups",
    "forward_extremities",
};

// True if `profile` should hydrate `table_name`'s rows into memory.
// `federation_worker` allows only federation_worker_table_allowlist; a
// table absent from it is never hydrated by the worker regardless of
// backend. Pure and header-testable: exercised directly by
// tests/unit/test_worker_db_uri.cpp without a database connection.
[[nodiscard]] constexpr auto table_load_profile_includes(std::string_view table_name, TableLoadProfile profile) noexcept
    -> bool
{
    if (profile == TableLoadProfile::full)
    {
        return true;
    }
    for (auto const& allowed : federation_worker_table_allowlist)
    {
        if (allowed == table_name)
        {
            return true;
        }
    }
    return false;
}

struct PersistentUser final
{
    std::string user_id{};
    std::string password_hash{};
    bool locked{false};
    bool suspended{false};
    bool admin{false};
    // Permanent, irreversible account closure (spec: POST /account/deactivate).
    // Distinct from `locked`/`suspended`, which are reversible admin actions: a
    // deactivated account can never log in again and its localpart is never
    // reissued.
    bool deactivated{false};
};

struct PersistentDevice final
{
    std::string user_id{};
    std::string device_id{};
    std::string display_name{};
};

struct PersistentAccessToken final
{
    std::string user_id{};
    std::string device_id{};
    std::string token_hash{};
    bool revoked{false};
    // Server-side expiry. nullopt = no expiry (legacy rows / unset). Enforced by
    // find_session and the refresh-token lookup so an expired token is rejected
    // even when not revoked, forcing the refresh/re-login flow.
    std::optional<std::chrono::system_clock::time_point> expires_at{};
    // For an access token minted by POST /refresh: the hash of the refresh
    // token that was presented. Its first use revokes that refresh token
    // (ADR-0074). Empty for tokens minted any other way.
    std::string predecessor_refresh_hash{};
};

struct PersistentRefreshToken final
{
    std::string user_id{};
    std::string device_id{};
    std::string token_hash{};
    bool revoked{false};
    std::optional<std::chrono::system_clock::time_point> expires_at{};
    // For a refresh token minted by POST /refresh: the hash of the refresh
    // token it replaces, which stays valid until this pair is first used
    // (ADR-0074). Empty for tokens minted at login.
    std::string predecessor_hash{};
};

// A stored server signing-key row.
//
// `secret_key` holds the at-rest form of this server's own Ed25519 signing
// secret: since 0.12.5 always `secretbox:v1:<base64>` ciphertext, and for a row
// written by an older release possibly legacy plaintext base64.
//
// 0.12.5 audit, finding 17: it is a std::string, so the in-memory persistent
// store held that material in unpinned heap memory that was freed without being
// wiped -- and a std::string reallocating (or a row being copied out of the
// store's vector) left further unwiped copies behind. The field cannot become a
// core::SecretBuffer without making the whole row move-only, which the store's
// row vectors and every query path depend on not being; so instead the row
// zeroises the field itself. Copies each wipe their own buffer, and a move
// wipes what it leaves behind, so no path drops a secret without erasing it.
//
// This is a mitigation, not the guarantee SecretBuffer gives: the bytes are
// still swappable while live. What actually keeps them safe at rest is that
// they are ciphertext -- see finding 1 and crypto::signing_secret_box_key.
struct PersistentServerSigningKey final
{
    std::string server_name{};
    std::string key_id{};
    std::string public_key{};
    std::uint64_t valid_until_ts{0U};
    std::string secret_key{}; // at-rest ciphertext (legacy rows: plaintext base64)

    PersistentServerSigningKey() = default;
    PersistentServerSigningKey(std::string server_name_value, std::string key_id_value, std::string public_key_value,
                               std::uint64_t valid_until_ts_value, std::string secret_key_value = {});
    PersistentServerSigningKey(PersistentServerSigningKey const& other);
    auto operator=(PersistentServerSigningKey const& other) -> PersistentServerSigningKey&;
    PersistentServerSigningKey(PersistentServerSigningKey&& other) noexcept;
    auto operator=(PersistentServerSigningKey&& other) noexcept -> PersistentServerSigningKey&;
    ~PersistentServerSigningKey();
};

struct PersistentFederationDestination final
{
    std::string server_name{};
    std::string state{"idle"};
    std::uint64_t retry_after_ts{0U};
    std::uint64_t last_success_ts{0U};
    std::uint32_t consecutive_failures{0U};
};

struct PersistentFederationTransaction final
{
    std::string transaction_id{};
    std::string server_name{};
    std::string method{"PUT"};
    std::string target{};
    std::string origin{};
    std::string origin_server_ts{};
    std::string body{};
    std::uint32_t retry_count{0U};
    std::uint64_t next_retry_ts{0U};
};

struct PersistentRoom final
{
    std::string room_id{};
    std::string creator_user_id{};
    bool directory_public{false};
};

struct PersistentMembership final
{
    std::string room_id{};
    std::string user_id{};
    std::string membership{"join"};
    std::uint64_t stream_ordering{0U};
};

struct PersistentInvite final
{
    std::string room_id{};
    std::string user_id{};
    std::string sender_user_id{};
    std::string event_id{};
    std::string signed_event_json{};
    std::vector<std::string> invite_state_events_json{};
    std::uint64_t stream_ordering{0U};
};

struct PersistentEvent final
{
    std::string event_id{};
    std::string room_id{};
    std::string sender_user_id{};
    std::string json{};
    std::uint64_t depth{0U};
    std::uint64_t stream_ordering{0U};
    std::vector<std::string> prev_event_ids{};
    std::vector<std::string> auth_event_ids{};
    std::vector<events::EventSignature> signatures{};
    // ADR-0064 receipt-order status: "accepted" | "soft_failed" | "rejected" |
    // "outlier". Appended as the last member (default "accepted") so every
    // pre-existing brace-init call site that does not mention it keeps
    // compiling. See database::set_event_status/find_event_status.
    std::string status{"accepted"};
};

struct PersistentStateEvent final
{
    std::string room_id{};
    std::string event_type{};
    std::string state_key{};
    std::string event_id{};
};

// Tracks the state event that was replaced when a new state event was stored.
// Used to populate unsigned.replaces_state in the client event format.
struct PersistentStateTransition final
{
    std::string room_id{};
    std::string event_type{};
    std::string state_key{};
    std::string event_id{};
    std::string previous_event_id{};
};

struct PersistentEventEdge final
{
    std::string event_id{};
    std::string prev_event_id{};
};

struct PersistentEventAuth final
{
    std::string event_id{};
    std::string auth_event_id{};
};

struct PersistentEventSignature final
{
    std::string event_id{};
    std::string server_name{};
    std::string key_id{};
    std::string signature{};
};

struct PersistentDeviceKey final
{
    std::string user_id{};
    std::string device_id{};
    std::string json{};
};

struct PersistentOneTimeKey final
{
    std::string user_id{};
    std::string device_id{};
    std::string key_id{};
    std::string json{};
};

struct PersistentFallbackKey final
{
    std::string user_id{};
    std::string device_id{};
    std::string key_id{};
    std::string json{};
};

struct PersistentCrossSigningKey final
{
    std::string user_id{};
    std::string key_type{};
    std::string json{};
};

struct PersistentKeySignature final
{
    std::string signer_user_id{};
    std::string target_user_id{};
    std::string target_device_id{};
    std::string json{};
};

struct PersistentKeyBackupVersion final
{
    std::string user_id{};
    std::string version{};
    std::string json{};
};

struct PersistentKeyBackupSession final
{
    std::string user_id{};
    std::string version{};
    std::string room_id{};
    std::string session_id{};
    std::string json{};
};

struct PersistentLocalMedia final
{
    std::string media_id{};
    std::string owner_user_id{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    bool quarantined{false};
    bool removed{false};
    // See media::LocalMediaRecord::legacy_endpoint_visible.
    bool legacy_endpoint_visible{true};
};

struct PersistentRemoteMedia final
{
    std::string server_name{};
    std::string media_id{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    bool quarantined{false};
};

struct PersistentMediaBlob final
{
    std::string storage_id{};
    std::string hash_algorithm{};
    std::string digest{};
    std::uint64_t size_bytes{0U};
    std::string bytes{};
    std::uint64_t ref_count{0U};
};

struct PersistentPolicyRule final
{
    std::string rule_id{};
    std::string scope{};
    std::string entity{};
    std::string action{};
    std::string reason{};
};

// AUTH-1: how many of the most recent audit rows the process keeps in memory,
// in `PersistentStore::audit_log` and in `LocalDatabase::audit_events`. The
// database holds every row; memory holds a window.
inline constexpr auto max_in_memory_audit_events = std::size_t{1024U};

// AUTH-11: the most committed statements `enable_statement_capture` will hold,
// however large a capacity is requested.
inline constexpr auto max_statement_capture_capacity = std::size_t{65536U};

struct PersistentAuditEvent final
{
    std::string category{};
    std::string event_type{};
    std::string actor{};
    std::string target{};
    std::string reason{};
};

struct PersistentAdminAction final
{
    std::string admin_user_id{};
    std::string action{};
    std::string target{};
};

// Matrix account-data row. Per-room account data is identified by a
// non-empty `room_id`; an empty `room_id` denotes global account data.
// The runtime keeps both classes in the same in-memory collection;
// they are persisted to separate backend tables (`account_data` /
// `room_account_data`) because the v1 schema's primary key on
// `account_data` did not include `room_id`.
struct PersistentAccountData final
{
    std::string user_id{};
    std::string room_id{};
    std::string event_type{};
    std::string content_json{};
    std::uint64_t stream_id{0U};
};

// Pending to-device message. Sender pushes the row at send time; the
// recipient's /sync drain advances `stream_id` past the row and the row
// is then removed. `stream_id` is monotonic across the server and reused
// as the sync next_batch token field for to-device.
struct PersistentToDeviceMessage final
{
    std::uint64_t stream_id{0U};
    std::string sender_user_id{};
    std::string target_user_id{};
    std::string target_device_id{};
    std::string message_type{};
    std::string content_json{};
    // CSAZ-10: epoch milliseconds when the row was enqueued. Used to enforce the
    // per-recipient TTL independently of sync acknowledgement.
    std::uint64_t created_at_ms{0U};
};

// Device-list change observed by a syncing user. `change_type` is
// "changed" or "left" per the Matrix spec. `observer_user_id` is the
// local user whose /sync will surface this change; `subject_user_id`
// is the user whose device list changed.
struct PersistentDeviceListChange final
{
    std::uint64_t stream_id{0U};
    std::string observer_user_id{};
    std::string subject_user_id{};
    std::string change_type{"changed"};
};

// Presence state for a Matrix user. Stored as the latest authoritative
// snapshot; the sync stream surfaces rows whose `stream_id` exceeds the
// caller's since-token.
struct PersistentPresence final
{
    std::uint64_t stream_id{0U};
    std::string user_id{};
    std::string presence{"offline"};
    std::string status_msg{};
    std::int64_t last_active_ago{0};
    bool currently_active{false};
};

// A client-uploaded sync filter. The server stores the raw JSON verbatim and
// returns an opaque `filter_id`; clients pass the id as a query parameter on
// subsequent /sync requests so the server can apply the filter criteria.
struct PersistentFilter final
{
    std::string user_id{};
    std::string filter_id{};
    std::string json{};
};

struct PersistentProfile final
{
    std::string user_id{};
    std::string displayname{};
    std::string avatar_url{};
};

// A third-party identifier (3PID) bound to a user account. `medium` is "email"
// or "msisdn"; `address` is the normalized identifier. `country` and
// `id_server` are nullopt when the binding was added without an identity-server
// round-trip (e.g. a registration-time validated email); `id_server` is set
// once the 3PID is bound at an identity server and `bound` records that the
// server-side IS binding exists. `added_at_ms`/`validated_at_ms` are epoch-ms.
// Primary key is (user_id, medium, address); a 3PID is globally unique to one
// account (enforced by threepid_in_use before insert).
struct PersistentThreePidBinding final
{
    std::string user_id{};
    std::string medium{};
    std::string address{};
    std::optional<std::string> country{};
    std::optional<std::string> id_server{};
    std::uint64_t added_at_ms{0U};
    std::uint64_t validated_at_ms{0U};
    bool bound{false};
    // IS validation pair (populated only for 3PIDs bound via a remote identity
    // server). Stored so a later unbind can drive IS auth mode 2 (sid +
    // client_secret) without a homeserver-signed request. See migration 007 and
    // docs/threat-model.md for the storage trade-off.
    std::optional<std::string> client_secret{};
    std::optional<std::string> sid{};
};

struct PersistentRoomAlias final
{
    std::string room_alias{};
    std::string room_id{};
};

// Idempotency record for a client-issued room send or send-to-device PUT.
// Keyed by (user_id, room_id, event_type, txn_id); room_id is empty for
// send-to-device entries. event_id holds the stored event ID for room sends
// and is empty for send-to-device (whose response is always {}).
struct PersistentClientTxnRecord final
{
    std::string user_id{};
    std::string room_id{};
    std::string event_type{};
    std::string txn_id{};
    std::string event_id{};
};

// A push notification pusher registered via `POST
// /_matrix/client/v3/pushers/set` (Matrix v1.19 CS API §push-notifications).
// Keyed by (user_id, app_id, pushkey) — the spec's uniqueness rule: setting a
// pusher with the same app_id and pushkey for the same user replaces it
// in-place rather than creating a second row. `kind` is "http" or "email".
// `data_url` and `data_format` mirror the pusher's `data` dictionary (the
// `url` and `format` keys); `data_url` is required for kind "http" and
// empty for "email". `profile_tag` is optional per spec and empty when unset.
// `data_extra_json` is a canonical-JSON-serialized object holding every
// OTHER member of the pusher's `data` dictionary at registration time (i.e.
// excluding `url`/`format`, which already have dedicated columns above) —
// Matrix v1.19 Push Gateway API requires the homeserver to forward the
// whole `data` dictionary minus `url` to the gateway, not just `format`.
// Empty string means "no extra members" (equivalent to serialized `{}`).
struct PersistentPusher final
{
    std::string user_id{};
    std::string app_id{};
    std::string pushkey{};
    std::string kind{};
    std::string app_display_name{};
    std::string device_display_name{};
    std::string profile_tag{};
    std::string lang{};
    std::string data_url{};
    std::string data_format{};
    std::string data_extra_json{};
};

// A recorded notification for `GET /_matrix/client/v3/notifications` (Matrix
// v1.19 CS API §push-notifications). Recorded once per (user_id, event_id)
// whenever push rule evaluation resolves `notify: true` for that recipient --
// independent of whether the recipient has a registered pusher or whether
// `server.push.enabled` is set (a user with push notifications turned off
// must still see their notification history when they open the client; see
// room_service.cpp's build_pending_push_deliveries). `actions` is the
// canonical-JSON-serialized actions array the matched rule produced;
// `highlight` mirrors its `set_tweak: highlight` action so `GET
// /notifications?only=highlight` can filter without re-parsing `actions`.
// `stream_ordering` is the triggering event's global stream position --
// unique per (user_id, event_id) row, since a recipient gets at most one
// notification per event -- and doubles as this table's pagination key,
// exactly like `events.stream_ordering` already does for GET /messages.
struct PersistentNotification final
{
    std::string user_id{};
    std::string room_id{};
    std::string event_id{};
    std::uint64_t stream_ordering{0U};
    std::uint64_t ts{0U};
    std::string actions{};
    std::string profile_tag{};
    bool highlight{false};
};

// A short-lived OpenID token minted by `POST
// /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19 CS
// API §OpenID) and redeemed by `GET /_matrix/federation/v1/openid/userinfo`
// (SS API §OpenID). Deliberately a table of its own, disjoint from
// PersistentAccessToken/access_tokens: this token authenticates nothing on
// the client-server surface -- its only valid use is the federation
// userinfo lookup -- so keeping it out of the access-token store and its
// lookup path is what prevents it from being replayed as a client-server
// bearer credential (see docs/threat-model.md). Unlike access tokens, every
// row has a finite expiry (the spec's `expires_in` is required), so
// expires_at is a plain time_point rather than optional.
struct PersistentOpenidToken final
{
    std::string user_id{};
    std::string token_hash{};
    std::chrono::system_clock::time_point expires_at{};
};

// A short-lived, single-use SSO login token minted when the SSO redirect
// flow completes and redeemed by `POST /login` with `type: m.login.token`
// (Matrix v1.19 CS API §"Client login via SSO"). Deliberately a table of its
// own, disjoint from PersistentAccessToken/access_tokens, for the same
// reason PersistentOpenidToken is: this token authenticates nothing on the
// ordinary client-server surface beyond the single /login exchange, so
// keeping it out of the access-token store and its lookup path is what
// prevents it from being replayed as a bearer credential. `used` enforces
// single-use redemption (spec: "opaque token, suitable for use with
// m.login.token"). The `device_id` the eventual session binds to comes from
// the `POST /login` request body itself, exactly as it already does for
// `m.login.password` -- this row only needs to answer "which user".
struct PersistentLoginToken final
{
    std::string user_id{};
    std::string token_hash{};
    std::chrono::system_clock::time_point expires_at{};
    bool used{false};
};

// The Application Service API's (Matrix v1.19) outbound
// `PUT /_matrix/app/v1/transactions/{txnId}` delivery cursor for one
// registered appservice. One row per appservice, keyed on `appservice_id`
// (the registration file's `id`, not a secret). Delivery replays forward
// through the `events` table's `stream_ordering`, so this row -- not a
// separate durable outbox -- is the entire persisted delivery state; see
// `room_service.cpp`'s appservice dispatch for how it is used:
//   - `next_txn_id`: the next FRESH transaction id to allocate. Monotonic,
//     never reused, so a retried transaction always carries the exact id
//     the appservice may have already partially processed.
//   - `delivered_stream_ordering`: high-water mark. Every event with
//     stream_ordering <= this value has been acknowledged (HTTP 200) by the
//     appservice.
//   - `pending_txn_id` / `pending_stream_ordering`: the currently in-flight
//     (sent, not yet acknowledged) batch, if any. `pending_txn_id == 0`
//     means no batch is in flight. A retry of that SAME batch reuses this
//     id and re-derives the identical event range
//     (delivered_stream_ordering, pending_stream_ordering] rather than
//     growing it -- the spec's "Homeservers MUST NOT alter (e.g. add more)
//     events they were going to send within that transaction ID on
//     retries."
struct PersistentAppserviceTxnCursor final
{
    std::string appservice_id{};
    std::uint64_t next_txn_id{1U};
    std::uint64_t delivered_stream_ordering{0U};
    std::uint64_t pending_txn_id{0U};
    std::uint64_t pending_stream_ordering{0U};
};

// A state group (ADR-0064, docs/adr/0064-spec-conformant-pdu-ingestion-with-
// delta-state-groups.md): the room state after some event, stored either as
// a full snapshot (`parent_state_group_id == nullopt`, `delta_depth == 0`)
// or as a delta from `parent_state_group_id` (`delta_depth` = parent's
// depth + 1, capped at `events::max_state_group_delta_depth`). The group's
// own rows (the full state for a snapshot, or just the changed entries for a
// delta) live in `state_group_state`/`PersistentStateGroupStateEntry`, keyed
// by `state_group_id`. See database::create_or_reuse_state_group and
// database::read_state_group_full_state.
struct PersistentStateGroup final
{
    std::string state_group_id{};
    std::string room_id{};
    std::optional<std::string> parent_state_group_id{};
    std::uint32_t delta_depth{0U};
};

// One row of a state group's own state: `state_group_id`'s snapshot or delta
// contains (event_type, state_key) -> event_id. See PersistentStateGroup.
struct PersistentStateGroupStateEntry final
{
    std::string state_group_id{};
    std::string event_type{};
    std::string state_key{};
    std::string event_id{};
};

// Maps an event to the state group holding the room's state immediately
// after it (ADR-0064). One row per event that has a known post-state.
struct PersistentEventStateGroup final
{
    std::string event_id{};
    std::string state_group_id{};
};

// A room's current forward extremity (ADR-0064): an accepted, non-soft-
// failed event with no accepted child yet. See
// database::update_forward_extremities.
struct PersistentForwardExtremity final
{
    std::string room_id{};
    std::string event_id{};
};

struct PersistentStore final
{
    PersistentStore() = default;
    PersistentStore(PersistentStore const& other)
        : open{other.open}
        , backend{other.backend}
        , postgresql_conninfo{other.postgresql_conninfo}
        , sqlite_path{other.sqlite_path}
        , schema{other.schema}
        , users{other.users}
        , devices{other.devices}
        , access_tokens{other.access_tokens}
        , refresh_tokens{other.refresh_tokens}
        , server_signing_keys{other.server_signing_keys}
        , federation_destinations{other.federation_destinations}
        , federation_transactions{other.federation_transactions}
        , rooms{other.rooms}
        , memberships{other.memberships}
        , invites{other.invites}
        , events{other.events}
        , state{other.state}
        , event_edges{other.event_edges}
        , event_auth{other.event_auth}
        , event_signatures{other.event_signatures}
        , device_keys{other.device_keys}
        , one_time_keys{other.one_time_keys}
        , fallback_keys{other.fallback_keys}
        , cross_signing_keys{other.cross_signing_keys}
        , key_signatures{other.key_signatures}
        , key_backup_versions{other.key_backup_versions}
        , key_backup_sessions{other.key_backup_sessions}
        , local_media{other.local_media}
        , remote_media{other.remote_media}
        , media_blobs{other.media_blobs}
        , audit_log{other.audit_log}
        , audit_log_evicted{other.audit_log_evicted}
        , admin_actions{other.admin_actions}
        , policy_rules{other.policy_rules}
        , account_data{other.account_data}
        , to_device_messages{other.to_device_messages}
        , device_list_changes{other.device_list_changes}
        , presence_states{other.presence_states}
        , filters{other.filters}
        , profiles{other.profiles}
        , account_threepids{other.account_threepids}
        , room_aliases{other.room_aliases}
        , client_txn_ids{other.client_txn_ids}
        , pushers{other.pushers}
        , notifications{other.notifications}
        , openid_tokens{other.openid_tokens}
        , login_tokens{other.login_tokens}
        , appservice_txn_cursors{other.appservice_txn_cursors}
        , state_groups{other.state_groups}
        , state_group_state{other.state_group_state}
        , event_state_groups{other.event_state_groups}
        , forward_extremities{other.forward_extremities}
        , captured_statements{other.captured_statements}
        , statement_capture_capacity{other.statement_capture_capacity}
        , force_next_persist_failures{other.force_next_persist_failures}
        , force_failure_statement_names{other.force_failure_statement_names}
        , statement_capture_mutex{std::make_unique<std::mutex>()}
        , server_signing_keys_mutex{std::make_unique<std::mutex>()}
        , next_sync_stream_id{other.next_sync_stream_id}
        , event_stream_watermark{other.event_stream_watermark}
        , max_to_device_messages_per_user_device{other.max_to_device_messages_per_user_device}
        , to_device_message_ttl_seconds{other.to_device_message_ttl_seconds}
    {
    }
    PersistentStore(PersistentStore&& other) noexcept = default;
    auto operator=(PersistentStore const& other) -> PersistentStore&
    {
        if (this == &other)
        {
            return *this;
        }
        open = other.open;
        backend = other.backend;
        postgresql_conninfo = other.postgresql_conninfo;
        sqlite_path = other.sqlite_path;
        schema = other.schema;
        users = other.users;
        devices = other.devices;
        access_tokens = other.access_tokens;
        refresh_tokens = other.refresh_tokens;
        server_signing_keys = other.server_signing_keys;
        federation_destinations = other.federation_destinations;
        federation_transactions = other.federation_transactions;
        rooms = other.rooms;
        memberships = other.memberships;
        invites = other.invites;
        events = other.events;
        state = other.state;
        event_edges = other.event_edges;
        event_auth = other.event_auth;
        event_signatures = other.event_signatures;
        device_keys = other.device_keys;
        one_time_keys = other.one_time_keys;
        fallback_keys = other.fallback_keys;
        cross_signing_keys = other.cross_signing_keys;
        key_signatures = other.key_signatures;
        key_backup_versions = other.key_backup_versions;
        key_backup_sessions = other.key_backup_sessions;
        local_media = other.local_media;
        remote_media = other.remote_media;
        media_blobs = other.media_blobs;
        audit_log = other.audit_log;
        audit_log_evicted = other.audit_log_evicted;
        admin_actions = other.admin_actions;
        policy_rules = other.policy_rules;
        account_data = other.account_data;
        to_device_messages = other.to_device_messages;
        device_list_changes = other.device_list_changes;
        presence_states = other.presence_states;
        filters = other.filters;
        profiles = other.profiles;
        account_threepids = other.account_threepids;
        room_aliases = other.room_aliases;
        client_txn_ids = other.client_txn_ids;
        pushers = other.pushers;
        notifications = other.notifications;
        openid_tokens = other.openid_tokens;
        login_tokens = other.login_tokens;
        appservice_txn_cursors = other.appservice_txn_cursors;
        state_groups = other.state_groups;
        state_group_state = other.state_group_state;
        event_state_groups = other.event_state_groups;
        forward_extremities = other.forward_extremities;
        captured_statements = other.captured_statements;
        statement_capture_capacity = other.statement_capture_capacity;
        force_next_persist_failures = other.force_next_persist_failures;
        force_failure_statement_names = other.force_failure_statement_names;
        statement_capture_mutex = std::make_unique<std::mutex>();
        server_signing_keys_mutex = std::make_unique<std::mutex>();
        next_sync_stream_id = other.next_sync_stream_id;
        event_stream_watermark = other.event_stream_watermark;
        max_to_device_messages_per_user_device = other.max_to_device_messages_per_user_device;
        to_device_message_ttl_seconds = other.to_device_message_ttl_seconds;
        return *this;
    }
    auto operator=(PersistentStore&& other) noexcept -> PersistentStore& = default;

    bool open{false};
    PersistentStoreBackend backend{PersistentStoreBackend::memory};
    std::string postgresql_conninfo{};
    // The DML-only role every PostgreSQL connection assumes after opening.
    // Carried on the store because connections are opened per operation from
    // the conninfo above: setting the role only on the bootstrap connection
    // would leave every subsequent read and write running as the login role,
    // which is the whole privilege separation defeated. Empty issues no
    // SET ROLE, preserving single-role deployments.
    std::string postgresql_runtime_role{};
    std::string sqlite_path{};
    SchemaState schema{};
    std::vector<PersistentUser> users{};
    std::vector<PersistentDevice> devices{};
    std::vector<PersistentAccessToken> access_tokens{};
    std::vector<PersistentRefreshToken> refresh_tokens{};
    std::vector<PersistentServerSigningKey> server_signing_keys{};
    std::vector<PersistentFederationDestination> federation_destinations{};
    std::vector<PersistentFederationTransaction> federation_transactions{};
    std::vector<PersistentRoom> rooms{};
    std::vector<PersistentMembership> memberships{};
    std::vector<PersistentInvite> invites{};
    std::vector<PersistentEvent> events{};
    std::vector<PersistentStateEvent> state{};
    std::vector<PersistentStateTransition> state_transitions{};
    // In-memory index over state_transitions keyed by (room_id, event_type, state_key, event_id)
    // and mapping to the vector offset. Rebuilt after hydration and updated on every insert so
    // client event serialization can look up unsigned.replaces_state in O(1).
    std::unordered_map<std::string, std::size_t> state_transition_index{};
    std::vector<PersistentEventEdge> event_edges{};
    std::vector<PersistentEventAuth> event_auth{};
    std::vector<PersistentEventSignature> event_signatures{};
    std::vector<PersistentDeviceKey> device_keys{};
    std::vector<PersistentOneTimeKey> one_time_keys{};
    std::vector<PersistentFallbackKey> fallback_keys{};
    std::vector<PersistentCrossSigningKey> cross_signing_keys{};
    std::vector<PersistentKeySignature> key_signatures{};
    std::vector<PersistentKeyBackupVersion> key_backup_versions{};
    std::vector<PersistentKeyBackupSession> key_backup_sessions{};
    std::vector<PersistentLocalMedia> local_media{};
    std::vector<PersistentRemoteMedia> remote_media{};
    std::vector<PersistentMediaBlob> media_blobs{};
    // In-memory window over the most recent `max_in_memory_audit_events` audit
    // rows (AUTH-1). The database table is the durable, complete record; this
    // deque is a bounded mirror for the admin views, so an unauthenticated flood
    // cannot grow process memory. Append through `append_audit_event`, and load
    // through `remember_audit_event`, never by push_back.
    std::deque<PersistentAuditEvent> audit_log{};
    // Rows that were appended and have since been evicted from `audit_log`.
    // `audit_log.size() + audit_log_evicted` is the number of rows this store has
    // seen since it was created or hydrated.
    std::uint64_t audit_log_evicted{0U};
    std::vector<PersistentAdminAction> admin_actions{};
    std::vector<PersistentPolicyRule> policy_rules{};
    std::vector<PersistentAccountData> account_data{};
    std::vector<PersistentToDeviceMessage> to_device_messages{};
    std::vector<PersistentDeviceListChange> device_list_changes{};
    std::vector<PersistentPresence> presence_states{};
    std::vector<PersistentFilter> filters{};
    std::vector<PersistentProfile> profiles{};
    std::vector<PersistentThreePidBinding> account_threepids{};
    std::vector<PersistentRoomAlias> room_aliases{};
    std::vector<PersistentClientTxnRecord> client_txn_ids{};
    std::vector<PersistentPusher> pushers{};
    std::vector<PersistentNotification> notifications{};
    std::vector<PersistentOpenidToken> openid_tokens{};
    std::vector<PersistentLoginToken> login_tokens{};
    std::vector<PersistentAppserviceTxnCursor> appservice_txn_cursors{};
    std::vector<PersistentStateGroup> state_groups{};
    std::vector<PersistentStateGroupStateEntry> state_group_state{};
    std::vector<PersistentEventStateGroup> event_state_groups{};
    std::vector<PersistentForwardExtremity> forward_extremities{};
    // Test-only capture of committed statements (AUTH-11). Empty and disabled
    // (`statement_capture_capacity == 0`) unless `enable_statement_capture` is
    // called, so production retains no statement or bound parameter after it
    // commits. When enabled it holds at most `statement_capture_capacity` of the
    // most recent statements; the oldest is dropped first.
    std::deque<PreparedStatement> captured_statements{};
    std::size_t statement_capture_capacity{0U};
    // Test-only counter: when non-zero the memory backend decrements this and
    // returns false from the next that many persist operations, simulating a
    // durable-store failure without involving a real database. Production never
    // touches this field.
    std::size_t force_next_persist_failures{0U};
    // Test-only set: persist operations whose statement name is in this set fail
    // once (the name is removed as it fires). This lets tests fail a specific
    // revocation statement without disturbing earlier password/device updates.
    // Production never touches this field.
    std::unordered_set<std::string> force_failure_statement_names{};
    // Guards captured_statements and statement_capture_capacity. Written by
    // commit_persistent_transaction from multiple concurrent room-stripe paths
    // and read by sensitive_values_are_redacted. Kept separate from the room
    // stripe locks because capture access is independent of any room. Wrapped
    // in unique_ptr so PersistentStore remains moveable.
    mutable std::unique_ptr<std::mutex> statement_capture_mutex{std::make_unique<std::mutex>()};
    // Guards server_signing_keys. The remote-key resolver stores and reads
    // keys from federation relay threads and from backfill, both with the
    // runtime mutex released, so after start-up hydration every access goes
    // through store_server_signing_key, find_server_signing_key or
    // snapshot_server_signing_keys, which take this lock. It is never held
    // across a database write or a network call. Wrapped in unique_ptr so
    // PersistentStore remains moveable.
    mutable std::unique_ptr<std::mutex> server_signing_keys_mutex{std::make_unique<std::mutex>()};
    // Monotonic stream id used by /sync surfaces (to_device, device_list
    // changes, presence). Incremented before each new row is persisted so
    // the row's stream_id strictly exceeds every previous one and clients
    // can compare against the since-token.
    std::uint64_t next_sync_stream_id{0U};
    // Highest timeline stream_ordering ever allocated, persisted to the
    // event_stream_watermark singleton. Some allocations (membership stream
    // positions, soft-failed events) are not backed by a persisted event
    // row, so rebuilding the counter from max(events.stream_ordering) alone
    // regresses it across restarts — which invalidates every pos/since token
    // clients persisted from the previous lifetime.
    std::uint64_t event_stream_watermark{0U};
    // CSAZ-10: per-recipient to-device queue limits, copied from
    // server.client_api at runtime startup so the database layer can enforce
    // them without depending on the config module. A cap of zero disables the
    // bound (not recommended); a TTL of zero disables age-based eviction.
    std::uint32_t max_to_device_messages_per_user_device{10000U};
    std::uint32_t to_device_message_ttl_seconds{604800U};
};

struct PersistentStoreOpenResult final
{
    bool ok{false};
    std::string reason{};
    PersistentStore store{};
};

// Freshly-read rows for a single room, scoped by room_id, used by reload_room
// to refresh one room's slice of a PersistentStore without re-reading the
// entire database. `room` is nullopt when the room no longer exists in the
// backing database (e.g. it was never local to this server after all); the
// other fields are empty in that case. `events` carries prev_event_ids,
// auth_event_ids, and signatures already reconstructed from the flat
// relation tables — see reconstruct_event_relations.
struct RoomReloadSnapshot final
{
    std::optional<PersistentRoom> room{};
    std::vector<PersistentMembership> memberships{};
    std::vector<PersistentInvite> invites{};
    std::vector<PersistentEvent> events{};
    std::vector<PersistentStateEvent> state{};
};

// Serialise a token expiry time_point to its TEXT column form (epoch-ms decimal
// string, empty for no expiry) and parse it back. Shared by the INSERT paths and
// the SQLite/PostgreSQL store hydration so the encoding stays consistent.
[[nodiscard]] auto expires_at_text(std::optional<std::chrono::system_clock::time_point> const& expires_at)
    -> std::string;
[[nodiscard]] auto parse_expires_at(std::string_view text) -> std::optional<std::chrono::system_clock::time_point>;

[[nodiscard]] auto open_persistent_store(SchemaState existing_state = {}) -> PersistentStoreOpenResult;
[[nodiscard]] auto open_sqlite_persistent_store(std::string const& path) -> PersistentStoreOpenResult;
[[nodiscard]] auto validate_persistent_store(PersistentStore const& store) -> MigrationValidationResult;
[[nodiscard]] auto commit_persistent_transaction(PersistentStore& store,
                                                 std::vector<PreparedStatement> const& statements) -> bool;
[[nodiscard]] auto store_user(PersistentStore& store, PersistentUser user) -> bool;
[[nodiscard]] auto update_user_password(PersistentStore& store, std::string_view user_id, std::string_view new_hash)
    -> bool;
// Sets the locked/suspended flags of a server-local user. Used by the admin
// account-moderation endpoints (PUT /v1/admin/lock and /suspend). Persists the
// change and mirrors it into the in-memory store. Returns false if the user is
// not found. Does NOT revoke access tokens — per spec v1.19, locking and
// suspending keep existing sessions intact and enforce via request-path gates.
// Marks a server-local user permanently deactivated. Irreversible: there is no
// corresponding "reactivate" call, by design (spec: "removing all ability for
// the user to login again").
[[nodiscard]] auto set_user_deactivated(PersistentStore& store, std::string_view user_id) -> bool;

[[nodiscard]] auto set_user_account_state(PersistentStore& store, std::string_view user_id, bool suspended, bool locked)
    -> bool;
[[nodiscard]] auto store_device(PersistentStore& store, PersistentDevice device) -> bool;
[[nodiscard]] auto store_access_token(PersistentStore& store, PersistentAccessToken token) -> bool;
[[nodiscard]] auto store_refresh_token(PersistentStore& store, PersistentRefreshToken token) -> bool;
[[nodiscard]] auto store_device_and_access_token(PersistentStore& store, std::optional<PersistentDevice> device,
                                                 PersistentAccessToken token) -> bool;
[[nodiscard]] auto revoke_access_token(PersistentStore& store, std::string_view token_hash) -> std::size_t;
[[nodiscard]] auto revoke_refresh_token(PersistentStore& store, std::string_view token_hash) -> std::size_t;
[[nodiscard]] auto revoke_access_tokens_for_user(PersistentStore& store, std::string_view user_id) -> std::size_t;
[[nodiscard]] auto revoke_access_tokens_for_device(PersistentStore& store, std::string_view user_id,
                                                   std::string_view device_id) -> std::size_t;
[[nodiscard]] auto revoke_refresh_tokens_for_user(PersistentStore& store, std::string_view user_id) -> std::size_t;
[[nodiscard]] auto revoke_refresh_tokens_for_device(PersistentStore& store, std::string_view user_id,
                                                    std::string_view device_id) -> std::size_t;
// ADR-0074: revokes the refresh tokens minted from `predecessor_hash` by an
// earlier POST /refresh whose response the client never received.
[[nodiscard]] auto revoke_refresh_tokens_with_predecessor(PersistentStore& store, std::string_view predecessor_hash)
    -> std::size_t;
// M-05: revokes every access and refresh token for `user_id` except those of
// `keep_device_id`. Used by the password-change logout_devices flow to drop the
// user's other sessions while keeping the caller's own alive.
//
// This replaced a revoke-all-then-restore-one-device pair. Restoring could not
// tell the tokens it had just revoked from ones revoked earlier by a logout or
// an admin action, so it resurrected them — and a password change is exactly
// what a user does after a compromise. There is deliberately no inverse
// "restore" helper: revocation is one-way by design. Do not add one.
[[nodiscard]] auto revoke_tokens_for_user_except_device(PersistentStore& store, std::string_view user_id,
                                                        std::string_view keep_device_id) -> std::size_t;
[[nodiscard]] auto update_device_display_name(PersistentStore& store, std::string_view user_id,
                                              std::string_view device_id, std::string_view display_name) -> bool;
[[nodiscard]] auto delete_device(PersistentStore& store, std::string_view user_id, std::string_view device_id) -> bool;
[[nodiscard]] auto store_server_signing_key(PersistentStore& store, PersistentServerSigningKey key) -> bool;
[[nodiscard]] auto find_server_signing_key(PersistentStore const& store, std::string_view server_name,
                                           std::string_view key_id) -> std::optional<PersistentServerSigningKey>;
// A copy of every stored signing key, taken under server_signing_keys_mutex.
// Callers that iterate the keys use this rather than the vector itself.
[[nodiscard]] auto snapshot_server_signing_keys(PersistentStore const& store)
    -> std::vector<PersistentServerSigningKey>;
[[nodiscard]] auto store_federation_destination(PersistentStore& store, PersistentFederationDestination destination)
    -> bool;
[[nodiscard]] auto store_federation_transaction(PersistentStore& store, PersistentFederationTransaction transaction)
    -> bool;
[[nodiscard]] auto delete_federation_transaction(PersistentStore& store, std::string_view transaction_id) -> bool;
enum class MembershipStoreResult
{
    stored,
    already_exists,
    error,
};

[[nodiscard]] auto store_room(PersistentStore& store, PersistentRoom room) -> bool;
// Persists a room's directory visibility before updating its in-memory mirror.
[[nodiscard]] auto set_room_directory_public(PersistentStore& store, std::string_view room_id, bool directory_public)
    -> bool;
// Re-derives every PersistentEvent's prev_event_ids/auth_event_ids/signatures
// from the flat event_edges/event_auth/event_signatures tables. Those fields
// are populated directly when an event is stored fresh within a process's
// lifetime (store_event_with_state), but hydrating a store from disk
// (open_sqlite_persistent_store, open_postgresql_persistent_store, and
// reload_room below) only loads the flat relation tables — without this call
// every event's DAG-linkage fields silently read back empty, which breaks
// prev_events/auth_events selection for make_join and similar responses.
// Idempotent: safe to call on a store where the fields are already populated.
auto reconstruct_event_relations(PersistentStore& store) -> void;
// Re-reads a single room's rows (room, membership, invites, events, state,
// and the event relation tables scoped to that room's events) from the
// backing database and replaces this store's in-memory copy of that room
// with the fresh result. Used by the federation worker, whose PersistentStore
// is otherwise a point-in-time snapshot taken once at worker startup with no
// way to learn about rooms created or joined by the main process afterward
// (see docs/architecture.md, "Federation worker room staleness"). A no-op
// (returns true) for an in-memory-only store, since there is nothing on disk
// to reload from. Returns false only on a connection/query failure; a room
// that no longer exists is not an error — the room's stale rows are simply
// removed from this store's copy.
[[nodiscard]] auto reload_room(PersistentStore& store, std::string_view room_id) -> bool;
[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> MembershipStoreResult;
[[nodiscard]] auto update_membership(PersistentStore& store, std::string_view room_id, std::string_view user_id,
                                     std::string_view new_membership, std::uint64_t stream_ordering) -> bool;
[[nodiscard]] auto delete_membership(PersistentStore& store, std::string_view room_id, std::string_view user_id)
    -> bool;
[[nodiscard]] auto upsert_invite(PersistentStore& store, PersistentInvite invite) -> bool;
[[nodiscard]] auto delete_invite(PersistentStore& store, std::string_view room_id, std::string_view user_id) -> bool;
[[nodiscard]] auto find_invite(PersistentStore const& store, std::string_view room_id, std::string_view user_id)
    -> std::optional<PersistentInvite>;
[[nodiscard]] auto store_room_with_membership(PersistentStore& store, PersistentRoom room,
                                              PersistentMembership membership) -> bool;
[[nodiscard]] auto store_event(PersistentStore& store, PersistentEvent event) -> bool;
[[nodiscard]] auto store_state(PersistentStore& store, PersistentStateEvent state) -> bool;
[[nodiscard]] auto store_event_with_state(PersistentStore& store, PersistentEvent event,
                                          std::optional<PersistentStateEvent> state) -> bool;

// ---- ADR-0064 phase A: delta state groups, forward extremities, event status ----
//
// Creates a new state group for `room_id` holding `full_state` (the complete
// room state — every (event_type, state_key) -> event_id pair — after some
// event), or reuses `parent_state_group_id` unchanged when `full_state` is
// exactly the parent's own full state (read via
// read_state_group_full_state). When a new group is needed:
//   - `parent_state_group_id == nullopt`, or the parent's delta_depth + 1
//     would exceed events::max_state_group_delta_depth, or `full_state` is
//     missing a (event_type, state_key) the parent has (deltas never encode
//     deletions — state resolution never drops a key present in any fork, so
//     this should not happen, but it is handled safely) -> a full snapshot
//     is written under `new_state_group_id` (delta_depth = 0).
//   - Otherwise only the entries of `full_state` that differ from the
//     parent's are written, under `new_state_group_id`, as a delta
//     (delta_depth = parent's + 1).
// Returns the id of the group that now holds `full_state` (the reused
// parent id, or `new_state_group_id`), or nullopt if the parent id does not
// resolve to a valid group (missing, cyclic, or over-long chain) or the
// backend write fails.
[[nodiscard]] auto create_or_reuse_state_group(PersistentStore& store, std::string_view room_id,
                                               std::string_view new_state_group_id,
                                               std::optional<std::string> const& parent_state_group_id,
                                               std::vector<PersistentStateGroupStateEntry> const& full_state)
    -> std::optional<std::string>;

// Returns `state_group_id`'s own row (its room, parent, and delta depth —
// not its resulting state; see read_state_group_full_state for that), or
// nullopt if no such group exists.
[[nodiscard]] auto find_state_group(PersistentStore const& store, std::string_view state_group_id)
    -> std::optional<PersistentStateGroup>;

// Reads `state_group_id`'s full resulting state by walking parent links back
// to the nearest snapshot and applying every delta on the chain, newest
// first (a key already supplied by a newer group is never overwritten by an
// older one). Bounded to events::max_state_group_delta_depth + 1 hops and
// cycle-detected: a missing group, a cycle, or a chain longer than the bound
// fails closed, returning nullopt rather than a partial state map.
[[nodiscard]] auto read_state_group_full_state(PersistentStore const& store, std::string_view state_group_id)
    -> std::optional<std::vector<PersistentStateGroupStateEntry>>;

// Maps `event_id` to the state group holding the room's state immediately
// after it. Upserts: replaces any existing mapping for `event_id`.
[[nodiscard]] auto set_event_state_group(PersistentStore& store, std::string_view event_id,
                                         std::string_view state_group_id) -> bool;
// Returns the state group mapped to `event_id`, or nullopt if none is recorded.
[[nodiscard]] auto find_event_state_group(PersistentStore const& store, std::string_view event_id)
    -> std::optional<std::string>;

// Forward-extremity bookkeeping for storing an event (ADR-0064). When
// `accepted` is true, removes every id in `prev_event_ids` from `room_id`'s
// extremity set and adds `event_id` to it. When `accepted` is false (the
// event was soft-failed or rejected), this is a no-op: such events never
// become extremities and never remove one. Returns false only on a backend
// write failure.
[[nodiscard]] auto update_forward_extremities(PersistentStore& store, std::string_view room_id,
                                              std::string_view event_id, std::vector<std::string> const& prev_event_ids,
                                              bool accepted) -> bool;
// Returns `room_id`'s current forward extremity event ids, in no particular order.
[[nodiscard]] auto find_forward_extremities(PersistentStore const& store, std::string_view room_id)
    -> std::vector<std::string>;

// Sets the receipt-order status of `event_id` — one of "accepted",
// "soft_failed", "rejected", "outlier" (see PersistentEvent::status and
// ADR-0064). Persists the change and mirrors it into the in-memory event
// row. Returns false for an unrecognised status string, an unknown
// event_id, or a backend write failure.
[[nodiscard]] auto set_event_status(PersistentStore& store, std::string_view event_id, std::string_view status) -> bool;
// Returns event_id's current status, or nullopt if the event is not known
// to this store.
[[nodiscard]] auto find_event_status(PersistentStore const& store, std::string_view event_id)
    -> std::optional<std::string>;

// Rebuilds the in-memory state_transitions index from scratch. Called after
// SQLite/PostgreSQL hydration and after any direct backfill of the vector.
auto rebuild_state_transition_index(PersistentStore& store) -> void;

// Looks up a state transition by its primary tuple. Requires the index to be
// current; callers that modify the vector directly must call
// rebuild_state_transition_index() first.
[[nodiscard]] auto find_state_transition(PersistentStore const& store, std::string_view room_id,
                                         std::string_view event_type, std::string_view state_key,
                                         std::string_view event_id) -> PersistentStateTransition const*;

// Split version of store_event_with_state for callers that need to release locks
// around the backend commit. `prepare` validates in-memory pre-conditions and
// builds the prepared statements. `commit` writes them to the backend. `apply`
// mirrors the committed rows into the in-memory vectors. The three phases must be
// called in order on the same PreparedStateUpdate; prepare/apply are typically run
// under a per-room lock while commit runs without it so independent rooms can overlap.
struct PreparedStateUpdate final
{
    PersistentEvent event{};
    std::optional<PersistentStateEvent> state{};
    std::vector<PreparedStatement> statements{};
    bool state_already_existed{false};
    std::string previous_event_id{};
};

[[nodiscard]] auto prepare_store_event_with_state(PersistentStore& store, PersistentEvent event,
                                                  std::optional<PersistentStateEvent> state)
    -> std::optional<PreparedStateUpdate>;
auto apply_store_event_with_state(PersistentStore& store, PreparedStateUpdate const& update) -> void;
// Startup repair: finds events in store.events that are state events (JSON has a
// "state_key" field) but have no corresponding entry in store.state, and creates
// those missing entries. Returns the number of state entries created.
// Required when upgrading from versions that used !state_key.empty() to detect
// state events — that check silently dropped events with state_key="" such as
// m.room.create, m.room.join_rules, and m.room.power_levels.
[[nodiscard]] auto repair_missing_state_entries(PersistentStore& store) -> std::size_t;
[[nodiscard]] auto store_room_alias(PersistentStore& store, PersistentRoomAlias alias) -> bool;
[[nodiscard]] auto find_room_alias(PersistentStore const& store, std::string_view room_alias)
    -> std::optional<PersistentRoomAlias>;
[[nodiscard]] auto store_device_key(PersistentStore& store, PersistentDeviceKey key) -> bool;
[[nodiscard]] auto find_device_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id)
    -> std::optional<PersistentDeviceKey>;
[[nodiscard]] auto store_one_time_key(PersistentStore& store, PersistentOneTimeKey key) -> bool;
[[nodiscard]] auto claim_one_time_key(PersistentStore& store, std::string_view user_id, std::string_view device_id,
                                      std::string_view algorithm = {}) -> std::optional<PersistentOneTimeKey>;
[[nodiscard]] auto store_fallback_key(PersistentStore& store, PersistentFallbackKey key) -> bool;
[[nodiscard]] auto find_fallback_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id,
                                     std::string_view algorithm = {}) -> std::optional<PersistentFallbackKey>;
[[nodiscard]] auto store_cross_signing_key(PersistentStore& store, PersistentCrossSigningKey key) -> bool;
[[nodiscard]] auto store_key_signature(PersistentStore& store, PersistentKeySignature signature) -> bool;
[[nodiscard]] auto store_key_backup_version(PersistentStore& store, PersistentKeyBackupVersion version) -> bool;
[[nodiscard]] auto delete_key_backup_version(PersistentStore& store, std::string_view user_id, std::string_view version)
    -> bool;
[[nodiscard]] auto store_key_backup_session(PersistentStore& store, PersistentKeyBackupSession session) -> bool;
[[nodiscard]] auto delete_key_backup_room_sessions(PersistentStore& store, std::string_view user_id,
                                                   std::string_view version, std::string_view room_id) -> bool;
[[nodiscard]] auto delete_key_backup_session(PersistentStore& store, std::string_view user_id, std::string_view version,
                                             std::string_view room_id, std::string_view session_id) -> bool;
[[nodiscard]] auto delete_all_key_backup_sessions(PersistentStore& store, std::string_view user_id,
                                                  std::string_view version) -> bool;
[[nodiscard]] auto store_local_media(PersistentStore& store, PersistentLocalMedia media) -> bool;
[[nodiscard]] auto update_local_media_state(PersistentStore& store, std::string_view media_id, bool quarantined,
                                            bool removed) -> bool;
// Commit moderation metadata, optional blob removal and both audit records
// together. Repository projections must be changed only after this succeeds.
[[nodiscard]] auto commit_local_media_moderation(PersistentStore& store, std::string_view media_id, bool quarantined,
                                                 bool removed, PersistentAdminAction action, PersistentAuditEvent audit)
    -> bool;
[[nodiscard]] auto store_remote_media(PersistentStore& store, PersistentRemoteMedia media) -> bool;
[[nodiscard]] auto store_media_blob(PersistentStore& store, PersistentMediaBlob const& blob) -> bool;
[[nodiscard]] auto append_audit_event(PersistentStore& store, PersistentAuditEvent event) -> bool;
// Adds `event` to the bounded in-memory audit window without persisting it,
// evicting the oldest entry once `max_in_memory_audit_events` is reached. Used by
// append_audit_event after the durable write and by the backends when they
// hydrate the window from the audit_log table.
auto remember_audit_event(PersistentStore& store, PersistentAuditEvent event) -> void;
// The most rows `load_audit_events_by_type_prefix` will return, however large a
// limit is requested.
inline constexpr auto max_audit_query_rows = std::size_t{10000U};
// Audit rows whose event_type starts with `prefix`, newest first, at most `limit`
// (clamped to `max_audit_query_rows`). Reads the audit_log table, so it is not
// limited to the in-memory window; use it where an old row must not be lost, such
// as the admin safety-report listing. `prefix` is bound as a parameter and matched
// literally and case-sensitively: no LIKE pattern, so `%` and `_` are ordinary
// characters. A store with no database backend, or a backend read that fails,
// answers from the in-memory window instead (a failure is logged as a warning).
[[nodiscard]] auto load_audit_events_by_type_prefix(PersistentStore const& store, std::string_view prefix,
                                                    std::size_t limit) -> std::vector<PersistentAuditEvent>;
[[nodiscard]] auto append_admin_action(PersistentStore& store, PersistentAdminAction action) -> bool;
[[nodiscard]] auto store_policy_rule(PersistentStore& store, PersistentPolicyRule rule) -> bool;
[[nodiscard]] auto delete_policy_rule(PersistentStore& store, std::string_view rule_id) -> bool;
[[nodiscard]] auto store_account_data(PersistentStore& store, PersistentAccountData data) -> bool;
[[nodiscard]] auto enqueue_to_device_message(PersistentStore& store, PersistentToDeviceMessage message) -> bool;
[[nodiscard]] auto drain_to_device_messages(PersistentStore& store, std::string_view user_id,
                                            std::string_view device_id, std::uint64_t since_stream_id,
                                            std::uint64_t upper_stream_id) -> std::vector<PersistentToDeviceMessage>;
// Records that `subject_user_id`'s device list changed for `observer_user_id`.
//
// There is at most one row per (observer, subject) pair: a repeat replaces the
// earlier row and takes the newest stream position, so a client whose since
// token lies between the two positions still sees the change, and the table is
// bounded by observers x subjects however many EDUs a peer sends (audit FED-7).
// /sync only ever reports the latest change per subject
// (sync::collect_device_list_delta), so nothing is lost by replacing.
[[nodiscard]] auto record_device_list_change(PersistentStore& store, PersistentDeviceListChange change) -> bool;
// Records many changes as one unit: every change is validated first (any invalid
// one rejects the whole batch), the rows share ONE newly allocated stream
// position, and all writes go to the backend in a single transaction. An empty
// batch succeeds without touching the sync stream.
[[nodiscard]] auto record_device_list_changes(PersistentStore& store, std::vector<PersistentDeviceListChange> changes)
    -> bool;
[[nodiscard]] auto upsert_presence(PersistentStore& store, PersistentPresence state) -> bool;
// Store a sync filter uploaded by a client. On conflict the JSON is replaced.
[[nodiscard]] auto store_filter(PersistentStore& store, PersistentFilter filter) -> bool;
// Return the filter for (user_id, filter_id), or nullopt when not found.
[[nodiscard]] auto find_filter(PersistentStore const& store, std::string_view user_id, std::string_view filter_id)
    -> std::optional<PersistentFilter>;
// Create or replace a user profile row.
[[nodiscard]] auto store_profile(PersistentStore& store, PersistentProfile profile) -> bool;
// Return the profile for user_id, or nullopt when not found.
[[nodiscard]] auto find_profile(PersistentStore const& store, std::string_view user_id)
    -> std::optional<PersistentProfile>;
// Update only displayname for an existing profile row.
[[nodiscard]] auto update_profile_displayname(PersistentStore& store, std::string_view user_id,
                                              std::string_view displayname) -> bool;
// Update only avatar_url for an existing profile row.
[[nodiscard]] auto update_profile_avatar_url(PersistentStore& store, std::string_view user_id,
                                             std::string_view avatar_url) -> bool;
// Upsert a 3PID binding keyed by (user_id, medium, address). Persists the row
// and mirrors it into the in-memory vector (replacing any existing entry).
// Returns false on an empty user_id/medium/address or a backend write failure.
[[nodiscard]] auto store_account_threepid(PersistentStore& store, PersistentThreePidBinding binding) -> bool;
// Return the 3PID binding for (user_id, medium, address), or nullopt.
[[nodiscard]] auto find_account_threepid(PersistentStore const& store, std::string_view user_id,
                                         std::string_view medium, std::string_view address)
    -> std::optional<PersistentThreePidBinding>;
// Remove the 3PID binding for (user_id, medium, address). Returns false if no
// such binding exists or the backend delete fails.
[[nodiscard]] auto delete_account_threepid(PersistentStore& store, std::string_view user_id, std::string_view medium,
                                           std::string_view address) -> bool;
// Upsert a pusher keyed by (user_id, app_id, pushkey). Persists the row and
// mirrors it into the in-memory vector (replacing any existing entry with the
// same key). Returns false on an empty user_id/app_id/pushkey/kind or a
// backend write failure.
[[nodiscard]] auto store_pusher(PersistentStore& store, PersistentPusher pusher) -> bool;
// Return the pusher for (user_id, app_id, pushkey), or nullopt.
[[nodiscard]] auto find_pusher(PersistentStore const& store, std::string_view user_id, std::string_view app_id,
                               std::string_view pushkey) -> std::optional<PersistentPusher>;
// Remove the pusher for (user_id, app_id, pushkey). Returns false if no such
// pusher exists or the backend delete fails.
[[nodiscard]] auto delete_pusher(PersistentStore& store, std::string_view user_id, std::string_view app_id,
                                 std::string_view pushkey) -> bool;
// Return every pusher registered for user_id, in insertion order.
[[nodiscard]] auto list_pushers_for_user(PersistentStore const& store, std::string_view user_id)
    -> std::vector<PersistentPusher>;
// Upsert a notification keyed by (user_id, event_id) -- see
// PersistentNotification. Persists the row, mirrors it into the in-memory
// vector, and then prunes user_id's oldest rows beyond max_per_user
// (default 1000)
// so `notifications` cannot grow without bound under sustained message
// volume. Returns false on an empty user_id/room_id/event_id or a backend
// write failure.
[[nodiscard]] auto store_notification(PersistentStore& store, PersistentNotification notification,
                                      std::size_t max_per_user = 1000U) -> bool;
// Return every notification recorded for user_id, in insertion
// (stream_ordering) order ascending. Callers apply from/limit/only
// pagination and filtering.
[[nodiscard]] auto list_notifications_for_user(PersistentStore const& store, std::string_view user_id)
    -> std::vector<PersistentNotification>;
// Insert an OpenID token row. Persists it, mirrors it into the in-memory
// vector, and then prunes every already-expired row (across all users) so
// `openid_tokens` cannot grow without bound -- the time-based analogue of
// store_notification's per-user count cap, appropriate here because an
// OpenID token's natural retention bound is its own short expiry rather
// than a row count. Returns false on an empty user_id/token_hash or a
// backend write failure.
[[nodiscard]] auto store_openid_token(PersistentStore& store, PersistentOpenidToken token) -> bool;
// Insert a login token row (see PersistentLoginToken). Persists it, mirrors
// it into the in-memory vector, then prunes every already-expired row
// (across all users) so `login_tokens` cannot grow without bound -- the
// same retention strategy store_openid_token uses. Returns false on an
// empty user_id/token_hash or a backend write failure.
[[nodiscard]] auto store_login_token(PersistentStore& store, PersistentLoginToken token) -> bool;
// Atomically redeems a login token: looks up an unused, unexpired row whose
// hash matches one of `candidate_hashes`, marks it used (both in the
// backend and the in-memory mirror) so it cannot be redeemed twice, and
// returns the bound user_id. Returns nullopt if no such row exists (unknown,
// expired, or already-used token) or if marking it used fails -- fail
// closed rather than hand back a user_id for a token that might still be
// replayable.
[[nodiscard]] auto consume_login_token(PersistentStore& store, std::vector<std::string> const& candidate_hashes)
    -> std::optional<std::string>;
// Returns the persisted delivery cursor for `appservice_id`, or a
// default-constructed PersistentAppserviceTxnCursor (next_txn_id=1,
// everything else 0/absent) if no row exists yet -- the "never delivered
// anything" starting state, not an error.
[[nodiscard]] auto find_appservice_txn_cursor(PersistentStore const& store, std::string_view appservice_id)
    -> PersistentAppserviceTxnCursor;
// Upserts the full cursor row for one appservice (keyed on appservice_id).
// Callers pass the complete desired state; this is not an incremental
// update.
[[nodiscard]] auto store_appservice_txn_cursor(PersistentStore& store, PersistentAppserviceTxnCursor cursor) -> bool;
// Look up a previous idempotent send result. Returns the stored event_id
// (or empty string for to-device sends) if the (user_id, room_id,
// event_type, txn_id) tuple was already committed; nullopt otherwise.
[[nodiscard]] auto find_client_txn_event_id(PersistentStore const& store, std::string_view user_id,
                                            std::string_view room_id, std::string_view event_type,
                                            std::string_view txn_id) -> std::optional<std::string>;
// Record an idempotent send result. Silently succeeds if the key already
// exists (the original store wins — the client may retry while still in-flight).
[[nodiscard]] auto store_client_txn(PersistentStore& store, PersistentClientTxnRecord record) -> bool;

// Sets `store.next_sync_stream_id` to the maximum stream_id observed
// across every sync-surface row already loaded into memory (account_data,
// room account_data, to_device_messages, device_list_changes,
// presence_state) and the persisted `sync_stream_watermark` singleton.
// Backend hydration paths call this after populating the in-memory mirrors
// so a process restart preserves the monotonic invariant that
// next_sync_stream_id is strictly greater than every stream id a client
// has ever seen.
auto restore_sync_stream_id(PersistentStore& store) -> void;
// Atomically increments `store.next_sync_stream_id`, persists the new
// value to the `sync_stream_watermark` singleton, and returns it. Every
// sync-surface ID allocation must flow through this helper so a restart
// cannot roll the counter backward behind a client's since-token.
[[nodiscard]] auto allocate_sync_stream_id(PersistentStore& store) -> std::uint64_t;
// If `since_sync_stream_id` is greater than the server's current counter,
// advance the counter to that value and persist it. This recovers live
// deployments where the in-memory counter reached a higher value than the
// persisted watermark (for example, after adding the watermark table to a
// database whose typing/receipt surfaces advanced the counter).
[[nodiscard]] auto ensure_sync_stream_id_ahead_of(PersistentStore& store, std::uint64_t since_sync_stream_id) -> bool;
// Persists `watermark` (the highest allocated timeline stream_ordering) to
// the `event_stream_watermark` singleton and mirrors it into
// `store.event_stream_watermark`. Every stream_ordering allocation must
// record its value here so a restart cannot roll the timeline counter
// backward behind a pos/since token a client already holds.
[[nodiscard]] auto persist_event_stream_watermark(PersistentStore& store, std::uint64_t watermark) -> bool;
// AUTH-11: turns on retention of committed statements, bounded to `capacity`
// (clamped to `max_statement_capture_capacity`). A capacity of zero disables
// capture and drops anything held. Intended for tests that assert on the SQL and
// bound parameters a store operation produced; production never calls it.
auto enable_statement_capture(PersistentStore& store, std::size_t capacity) -> void;
// Test-only: make the next `count` memory-backend persist operations fail. This
// lets revocation paths prove they do not ignore a durable-store write failure.
// Production never calls this.
auto force_next_persist_failures(PersistentStore& store, std::size_t count) -> void;
// Test-only: make the memory-backend persist operation for `statement_name` fail
// once. This lets tests fail a specific revocation statement even when the
// function performs other persists first. Production never calls this.
auto force_persist_failure_for_statement(PersistentStore& store, std::string_view statement_name) -> void;
// True when statement capture is enabled and no captured parameter that looks
// like a token or secret was left unmarked as sensitive. Fails closed: with
// capture disabled there is nothing to inspect, so it returns false rather than
// passing on an empty buffer.
[[nodiscard]] auto sensitive_values_are_redacted(PersistentStore const& store) noexcept -> bool;

namespace detail
{

    [[nodiscard]] auto persist_statement_to_backend(PersistentStore& store, PreparedStatement const& statement) -> bool;
    [[nodiscard]] auto persist_transaction_to_backend(PersistentStore& store,
                                                      std::vector<PreparedStatement> const& statements) -> bool;
    [[nodiscard]] auto persist_transaction_to_postgresql(PersistentStore const& store,
                                                         std::vector<PreparedStatement> const& statements) -> bool;

    // Backend-specific half of reload_room: reads just this room's rows from
    // the database (not the in-memory store) and returns them with the event
    // relation fields already reconstructed. Returns nullopt on a
    // connection/query failure; a room that no longer exists is a successful
    // result with `room == nullopt` inside the snapshot, not a nullopt return.
    [[nodiscard]] auto load_room_snapshot_from_backend(PersistentStore const& store, std::string_view room_id)
        -> std::optional<RoomReloadSnapshot>;
    // Backend half of load_audit_events_by_type_prefix: newest first, already
    // bounded by `limit`. Returns nullopt on a connection/query failure.
    [[nodiscard]] auto load_audit_events_from_backend(PersistentStore const& store, std::string_view prefix,
                                                      std::size_t limit)
        -> std::optional<std::vector<PersistentAuditEvent>>;
    [[nodiscard]] auto load_audit_events_from_sqlite(std::string const& path, std::string_view prefix,
                                                     std::size_t limit)
        -> std::optional<std::vector<PersistentAuditEvent>>;
    [[nodiscard]] auto load_audit_events_from_postgresql(std::string_view conninfo, std::string_view runtime_role,
                                                         std::string_view prefix, std::size_t limit)
        -> std::optional<std::vector<PersistentAuditEvent>>;
    [[nodiscard]] auto load_room_snapshot_from_sqlite(std::string const& path, std::string_view room_id)
        -> std::optional<RoomReloadSnapshot>;
    [[nodiscard]] auto load_room_snapshot_from_postgresql(std::string_view conninfo, std::string_view runtime_role,
                                                          std::string_view room_id)
        -> std::optional<RoomReloadSnapshot>;

} // namespace detail

} // namespace merovingian::database
