// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/CopyableMutex.hpp"
#include "merovingian/database/CappedAccountDataStore.hpp"
#include "merovingian/database/CredentialTable.hpp"
#include "merovingian/database/DeferredPduAwaits.hpp"
#include "merovingian/database/DeferredPduUpsert.hpp"
#include "merovingian/database/EventStateGroupTable.hpp"
#include "merovingian/database/EventTable.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/MediaBlobRead.hpp"
#include "merovingian/database/MembershipProjection.hpp"
#include "merovingian/database/MembershipStoreResult.hpp"
#include "merovingian/database/MigrationApplyResult.hpp"
#include "merovingian/database/MigrationValidationResult.hpp"
#include "merovingian/database/MissingEventReferences.hpp"
#include "merovingian/database/PersistentAccessToken.hpp"
#include "merovingian/database/PersistentAccountData.hpp"
#include "merovingian/database/PersistentAdminAction.hpp"
#include "merovingian/database/PersistentAppserviceDirectoryEntry.hpp"
#include "merovingian/database/PersistentAppserviceOutboxEntry.hpp"
#include "merovingian/database/PersistentAppserviceTxnCursor.hpp"
#include "merovingian/database/PersistentAuditEvent.hpp"
#include "merovingian/database/PersistentBlobReferenceCount.hpp"
#include "merovingian/database/PersistentClientTxnRecord.hpp"
#include "merovingian/database/PersistentCrossSigningKey.hpp"
#include "merovingian/database/PersistentDeferredPdu.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentDeviceKey.hpp"
#include "merovingian/database/PersistentDeviceListChange.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentEventAuth.hpp"
#include "merovingian/database/PersistentEventEdge.hpp"
#include "merovingian/database/PersistentEventSignature.hpp"
#include "merovingian/database/PersistentFallbackKey.hpp"
#include "merovingian/database/PersistentFederationDestination.hpp"
#include "merovingian/database/PersistentFederationTransaction.hpp"
#include "merovingian/database/PersistentFilter.hpp"
#include "merovingian/database/PersistentForwardExtremity.hpp"
#include "merovingian/database/PersistentInvite.hpp"
#include "merovingian/database/PersistentKeyBackupSession.hpp"
#include "merovingian/database/PersistentKeyBackupVersion.hpp"
#include "merovingian/database/PersistentKeySignature.hpp"
#include "merovingian/database/PersistentLocalMedia.hpp"
#include "merovingian/database/PersistentLoginToken.hpp"
#include "merovingian/database/PersistentMediaBlob.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentNotification.hpp"
#include "merovingian/database/PersistentOneTimeKey.hpp"
#include "merovingian/database/PersistentOpenidToken.hpp"
#include "merovingian/database/PersistentPendingMediaUpload.hpp"
#include "merovingian/database/PersistentPolicyRule.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentProfile.hpp"
#include "merovingian/database/PersistentPusher.hpp"
#include "merovingian/database/PersistentReceipt.hpp"
#include "merovingian/database/PersistentRefreshToken.hpp"
#include "merovingian/database/PersistentRemoteMedia.hpp"
#include "merovingian/database/PersistentRemoteMediaRelease.hpp"
#include "merovingian/database/PersistentRoom.hpp"
#include "merovingian/database/PersistentRoomAlias.hpp"
#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStateGroup.hpp"
#include "merovingian/database/PersistentStateGroupStateEntry.hpp"
#include "merovingian/database/PersistentStateTransition.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/database/PersistentThreePidBinding.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/database/PersistentUser.hpp"
#include "merovingian/database/PreparedCurrentState.hpp"
#include "merovingian/database/PreparedStateGroup.hpp"
#include "merovingian/database/PreparedStateUpdate.hpp"
#include "merovingian/database/PreparedStatement.hpp"
#include "merovingian/database/RedactionState.hpp"
#include "merovingian/database/RoomAliasTable.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/database/RowGroupIndex.hpp"
#include "merovingian/database/RowKeyIndex.hpp"
#include "merovingian/database/SchemaState.hpp"
#include "merovingian/database/StateGroupEntryTable.hpp"
#include "merovingian/database/StateGroupTable.hpp"
#include "merovingian/database/TableLoadProfile.hpp"
#include "merovingian/database/UnusableCredentials.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::database
{

// The exact, minimal set of tables TableLoadProfile::federation_worker
// allows a store open to hydrate. This is an ALLOWLIST, not a denylist: a
// table absent from this array is excluded by default, so a future
// migration's new table is unreadable by the worker until someone adds it
// here deliberately (fail closed on the unknown, per the 0.12.13 audit N1
// part-2 review).
//
// Each entry was derived by tracing every FederationRuntimeState callback
// NOT overridden by WorkerEventLoop::run() (see
// src/federation_worker/WorkerEventLoop.cpp and
// src/federation_worker/AGENTS.md rule 3 for the overridden/relayed set —
// pdu_sink, membership_acceptor, invite_handler, edu_sink,
// one_time_keys_claim_provider, user_devices_provider,
// device_keys_query_provider, profile_query_provider, event_query_provider —
// whose DEFAULT local implementations are therefore never reached inside the
// worker process) to the PersistentStore fields it actually reads:
//
//   rooms               membership_template_provider (make_join/leave/knock),
//                       directory_query_provider, space_hierarchy_provider —
//                       LocalHttpRouter.cpp:1278, :1749, SpaceHierarchy.cpp
//   membership          directory_query_provider (joined servers for a room
//                       alias), SpaceHierarchy.cpp's joined_member_count —
//                       LocalHttpRouter.cpp:1749
//   current_state       membership_template_provider (auth_events),
//                       room_version_resolver, room_server_acl_provider,
//                       SpaceHierarchy.cpp (join_rule/is_space/space_children)
//                       — LocalHttpRouter.cpp:1335, :1830, :1838
//   events              membership_template_provider (forward extremities),
//                       build_backfill_pdus, build_state_response,
//                       build_state_ids_response,
//                       build_get_missing_events_response —
//                       LocalHttpRouter.cpp:1354, federation/EventQuery.cpp
//   event_edges         reconstruct_event_relations populates
//                       PersistentEvent::prev_event_ids from this table;
//                       without it every event's prev_events reads back
//                       empty for the make_join/backfill/missing_events
//                       routes above — database/PersistentStore.cpp
//                       reconstruct_event_relations
//   event_auth          same reconstruct_event_relations dependency, for
//                       PersistentEvent::auth_event_ids (auth-chain walks in
//                       build_state_response/build_state_ids_response)
//   event_signatures    same reconstruct_event_relations dependency, for
//                       PersistentEvent::signatures
//   room_aliases        directory_query_provider (find_room_alias) —
//                       LocalHttpRouter.cpp:1736
//   server_signing_keys remote_key_cache_probe / remote_key_resolver cache
//                       OTHER servers' keys here (find_cached_remote_key /
//                       store_server_signing_key) — LocalHttpRouter.cpp:
//                       1857-1871, federation/RemoteKeyCache.cpp. Column-
//                       restricted: the worker load path (see
//                       PostgresqlStore.cpp load_persistent_rows) never
//                       selects the secret_key column, and
//                       provision-federation-worker-role.sql grants SELECT
//                       on exactly the other four columns — so this entry
//                       never exposes this server's own signing secret even
//                       though the table name is shared with it.
//
//   state_groups        federation /state and /state_ids answer from the state
//                       group recorded for the event (ADR-0363), and
//                       ServerEventFilter judges history visibility on it
//                       (ADR-0064).
//   state_group_state   the same, for a group's own delta/snapshot rows.
//   event_state_groups  the same, for the event -> state group mapping.
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

// AUTH-1: how many of the most recent audit rows the process keeps in memory,
// in `PersistentStore::audit_log` and in `LocalDatabase::audit_events`. The
// database holds every row; memory holds a window.
inline constexpr auto max_in_memory_audit_events = std::size_t{1024U};

// AUTH-11: the most committed statements `enable_statement_capture` will hold,
// however large a capacity is requested.
inline constexpr auto max_statement_capture_capacity = std::size_t{65536U};

// Bounds on the retained set (R03, ADR-0165). A remote server chooses what
// reaches this table, so each limit is fixed rather than configurable and a
// PDU that would exceed one is not retained.
inline constexpr std::size_t max_deferred_pdus_per_room = 100U;
inline constexpr std::size_t max_deferred_pdus_total = 1000U;
inline constexpr std::size_t max_deferred_pdu_json_bytes = std::size_t{16U} * 1024U * 1024U;
// A retained PDU is dropped once it is this old, or after this many retries
// that did not place it, whichever comes first.
inline constexpr std::chrono::hours max_deferred_pdu_age{24};
inline constexpr std::uint32_t max_deferred_pdu_attempts = 10U;

struct PersistentStore;
struct PersistentStoreOpenResult;

namespace detail
{
    // DB-7, ADR-0154: each backend's pool of write connections, defined in its
    // own source file. Shared, not copied, by copies of a store.
    struct SqliteWritePool;
    struct PostgresqlWritePool;
    auto set_write_pool_limit(SqliteWritePool& pool, std::uint32_t limit) -> void;
    auto set_write_pool_limit(PostgresqlWritePool& pool, std::uint32_t limit) -> void;
    [[nodiscard]] auto write_pool_opened(SqliteWritePool const& pool) -> std::uint64_t;
    [[nodiscard]] auto write_pool_opened(PostgresqlWritePool const& pool) -> std::uint64_t;
} // namespace detail

// Called after an event has been added to `PersistentStore::events`, with the event's ID. The
// homeserver installs the redaction reconciler here (see homeserver/RedactionService.hpp).
using RedactionObserver = std::function<void(PersistentStore&, std::string const&)>;

struct PersistentStore final
{
    PersistentStore() = default;
    // Defaulted so a copy carries every member, including any added later (ADR-0523). The mutexes are
    // core::CopyableMutex, so a copy gets fresh, unlocked ones (ADR-0517): copy a store only while no other
    // thread is using it.
    PersistentStore(PersistentStore const& other) = default;
    PersistentStore(PersistentStore&& other) noexcept = default;
    auto operator=(PersistentStore const& other) -> PersistentStore& = default;
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
    // Worker snapshots never migrate, create files, or persist transactions.
    bool sqlite_read_only{false};
    SchemaState schema{};
    std::vector<PersistentUser> users{};
    std::vector<PersistentDevice> devices{};
    // The credential tables own their rows and index them (F-08): look up and revoke through their methods.
    CredentialTable<PersistentAccessToken> access_tokens{};
    CredentialTable<PersistentRefreshToken> refresh_tokens{};
    std::vector<PersistentServerSigningKey> server_signing_keys{};
    std::vector<PersistentFederationDestination> federation_destinations{};
    std::vector<PersistentFederationTransaction> federation_transactions{};
    // Position in `federation_transactions` of each transaction ID (ADR-0441). Kept by
    // store_federation_transaction(s) and delete_federation_transaction, rebuilt after hydration; trusted
    // only while `federation_transaction_indexed_rows == federation_transactions.size()` and the row a
    // position names carries the ID asked for, otherwise a lookup scans the vector.
    std::unordered_map<std::string, std::size_t> federation_transaction_index{};
    std::size_t federation_transaction_indexed_rows{0U};
    std::vector<PersistentRoom> rooms{};
    std::vector<PersistentMembership> memberships{};
    std::vector<PersistentInvite> invites{};
    // Positions in `memberships` of each room's rows (ADR-0437), so a reader of one room's members does not scan
    // every room's. Maintained by every writer in PersistentStore.cpp and rebuilt after hydration and
    // `reload_room`; only trusted while `membership_indexed_rows == memberships.size()` and each position it
    // names holds a row of the room, otherwise a reader scans `memberships`. A caller that edits the vector
    // directly (a test) thereby loses speed, never correctness. A row's room never changes in place.
    std::unordered_map<std::string, std::vector<std::size_t>> membership_room_index{};
    std::size_t membership_indexed_rows{0U};
    // (room, user) -> position in `memberships` (ADR-0603), same trust rule as `membership_room_index`.
    RowKeyIndex membership_key_index{};
    // The `events` table, indexed by event ID and by stream order (ADR-0215).
    EventTable events{};
    RedactionState redactions{};
    RedactionObserver redaction_observer{};
    std::vector<PersistentStateEvent> state{};
    // Positions in `state` by (room_id, event_type, state_key), and the positions of each room's
    // rows (ADR-0344). Maintained by every writer in PersistentStore.cpp and rebuilt after
    // hydration and `reload_room`; only trusted while `state_indexed_rows == state.size()` and
    // each position it names still holds the row asked for, otherwise a lookup scans `state`.
    // A caller that edits `state` directly (a test) thereby loses speed, never correctness.
    std::unordered_map<std::string, std::size_t> state_position_index{};
    std::unordered_map<std::string, std::vector<std::size_t>> state_room_index{};
    std::size_t state_indexed_rows{0U};
    std::vector<PersistentStateTransition> state_transitions{};
    // In-memory index over state_transitions keyed by (room_id, event_type, state_key, event_id)
    // and mapping to the vector offset. Rebuilt after hydration and updated on every insert so
    // client event serialization can look up unsigned.replaces_state in O(1).
    std::unordered_map<std::string, std::size_t> state_transition_index{};
    std::vector<PersistentEventEdge> event_edges{};
    std::vector<PersistentEventAuth> event_auth{};
    std::vector<PersistentEventSignature> event_signatures{};
    std::vector<PersistentDeviceKey> device_keys{};
    // Rows of `devices` and `device_keys` read to announce a device list, counted where they are read, so a test
    // can show the cost does not grow per device (ADR-0582).
    ExaminedRows device_table_rows_examined{};
    std::vector<PersistentOneTimeKey> one_time_keys{};
    std::vector<PersistentFallbackKey> fallback_keys{};
    // Indexes beside `users`, `devices`, `device_keys`, `one_time_keys` and `fallback_keys` (ADR-0603), so the
    // federation key and EDU paths look a user, a device or a device's keys up without scanning the table under
    // the runtime lock. Same trust rule as `state_position_index` (ADR-0344): used only while built for exactly
    // the vector's row count, otherwise the reader scans. Maintained by the writers in PersistentStore.cpp (a
    // writer that finds one stale rebuilds it first) and rebuilt after hydration. A one-time key claim erases by
    // moving the last row into the gap, so `one_time_keys` has no meaningful order.
    RowKeyIndex user_index{};
    RowGroupIndex device_user_index{};
    RowGroupIndex device_key_user_index{};
    RowGroupIndex one_time_key_device_index{};
    RowGroupIndex fallback_key_device_index{};
    RowGroupIndex cross_signing_key_user_index{};
    // Rows of `users`, `memberships`, `one_time_keys`, `fallback_keys` and the key backup tables read by the
    // indexed lookups, counted where they are read, so a test shows the cost does not grow with the table.
    ExaminedRows user_rows_examined{};
    ExaminedRows membership_rows_examined{};
    ExaminedRows key_rows_examined{};
    ExaminedRows key_backup_rows_examined{};
    std::vector<PersistentCrossSigningKey> cross_signing_keys{};
    std::vector<PersistentKeySignature> key_signatures{};
    // CSAZ-10: positions in `key_signatures` grouped by target_user_id, so
    // /keys/query merges one target's signatures without scanning every row.
    // Maintained by store_key_signature and rebuilt after hydration. It is only
    // trusted while `key_signature_indexed_rows == key_signatures.size()`; a
    // caller that pushes rows directly leaves the counts unequal and lookups
    // fall back to a scan until the next rebuild (key_signatures_for_target).
    std::unordered_map<std::string, std::vector<std::size_t>> key_signature_target_index{};
    std::size_t key_signature_indexed_rows{0U};
    std::vector<PersistentKeyBackupVersion> key_backup_versions{};
    std::vector<PersistentKeyBackupSession> key_backup_sessions{};
    // Key backup indexes (ADR-0606): a session by (user, version, room, session), the sessions of each (user,
    // version) and the versions of each user. Same trust rule as above. A deleted session or version erases by
    // moving the last row into the gap, so `key_backup_sessions` has no meaningful order.
    RowKeyIndex key_backup_session_index{};
    RowGroupIndex key_backup_version_session_index{};
    RowGroupIndex key_backup_user_version_index{};
    // The highest backup version number ever issued to each user, so a deleted version's number is
    // never issued again (F-60, ADR-0384). Persisted in `key_backup_version_counters`.
    std::unordered_map<std::string, std::uint64_t> key_backup_version_high_water{};
    std::vector<PersistentLocalMedia> local_media{};
    std::vector<PersistentRemoteMedia> remote_media{};
    std::vector<PersistentMediaBlob> media_blobs{};
    // Migration 026: reservations made by POST /_matrix/media/v1/create.
    std::vector<PersistentPendingMediaUpload> pending_media_uploads{};
    // F-16: rows of `pending_media_uploads` visited by commit_pending_media_upload.
    ExaminedRows pending_media_rows_examined{};
    // In-memory window over the most recent `max_in_memory_audit_events` audit
    // rows (AUTH-1). The database table is the durable, complete record; this
    // list is a bounded mirror for the admin views, so an unauthenticated flood
    // cannot grow process memory. Append through `append_audit_event`, and load
    // through `remember_audit_event`, never by push_back.
    std::list<PersistentAuditEvent> audit_log{};
    // Rows that were appended and have since been evicted from `audit_log`.
    // `audit_log.size() + audit_log_evicted` is the number of rows this store has
    // seen since it was created or hydrated.
    std::uint64_t audit_log_evicted{0U};
    std::vector<PersistentAdminAction> admin_actions{};
    std::vector<PersistentPolicyRule> policy_rules{};
    std::vector<PersistentAccountData> account_data{};
    // Positions in `account_data` of each user's rows (ADR-0440), so the per-recipient push and ignore
    // lookups read one user's few rows, not the table. Maintained by the account-data writers, rebuilt
    // after hydration; trusted only while `account_data_indexed_rows == account_data.size()`, otherwise a
    // lookup scans the vector. Rows are only ever appended or replaced in place.
    std::unordered_map<std::string, std::vector<std::size_t>> account_data_user_index{};
    std::size_t account_data_indexed_rows{0U};
    ExaminedRows account_data_rows_examined{};
    // Read receipts, local and federated. Write through store_receipt and
    // remove_receipt so the database row and this mirror stay in step.
    std::vector<PersistentReceipt> receipts{};
    std::vector<PersistentToDeviceMessage> to_device_messages{};
    std::vector<PersistentDeviceListChange> device_list_changes{};
    std::vector<PersistentPresence> presence_states{};
    std::vector<PersistentFilter> filters{};
    std::vector<PersistentProfile> profiles{};
    std::vector<PersistentThreePidBinding> account_threepids{};
    // A table class (ADR-0581): look up with find/aliases_of_room/count_for_creator, never by looping the rows.
    RoomAliasTable room_aliases{};
    std::vector<PersistentClientTxnRecord> client_txn_ids{};
    // Positions in `client_txn_ids`, so a request reads the records it needs without scanning every
    // record the server has ever stored (work under runtime.mutex is bounded by the request):
    // `client_txn_event_index` by event_id, for the transaction ID a sending device is given;
    // `client_txn_key_index` by (user_id, device_id, room_id, event_type, txn_id), for idempotency.
    // Maintained by store_client_txn and enqueue_to_device_messages_with_client_txn, rebuilt after
    // hydration and after a prune. They are trusted only while
    // `client_txn_indexed_rows == client_txn_ids.size()`; a caller that pushes rows directly leaves
    // the counts unequal and lookups fall back to a scan until the next rebuild. Only to-device rows
    // (room_id empty) are pruned, by prune_to_device_client_txns (ADR-0381); a room-send row stays,
    // because `unsigned.transaction_id` is served from it (ADR-0258).
    std::unordered_map<std::string, std::size_t> client_txn_event_index{};
    std::unordered_map<std::string, std::size_t> client_txn_key_index{};
    std::size_t client_txn_indexed_rows{0U};
    std::vector<PersistentPusher> pushers{};
    std::vector<PersistentNotification> notifications{};
    // Positions in `notifications` of each user's rows (ADR-0440). Same trust rule as
    // `account_data_user_index`. Rows are appended, replaced in place, or erased by moving the last row into
    // the gap, so the vector's order carries no meaning: read through `list_notifications_for_user`.
    std::unordered_map<std::string, std::vector<std::size_t>> notification_user_index{};
    std::size_t notification_indexed_rows{0U};
    ExaminedRows notification_rows_examined{};
    std::vector<PersistentOpenidToken> openid_tokens{};
    std::vector<PersistentLoginToken> login_tokens{};
    std::vector<PersistentAppserviceTxnCursor> appservice_txn_cursors{};
    // Events queued for appservices, kept sorted by (appservice_id, stream_ordering). See
    // PersistentAppserviceOutboxEntry.
    std::vector<PersistentAppserviceOutboxEntry> appservice_outbox{};
    // Rooms appservices have published to their networks' directories (ADR-0192). Write through
    // set_appservice_directory_entry so the row and this mirror stay in step.
    std::vector<PersistentAppserviceDirectoryEntry> appservice_directory{};
    // Federation PDUs retained for a retry (R03, ADR-0165). Bounded by the
    // max_deferred_pdu* constants; write through upsert_deferred_pdu and
    // remove_deferred_pdu so the bounds and the database row stay in step.
    std::vector<PersistentDeferredPdu> deferred_pdus{};
    // What each retained PDU waits for, by awaited event (ADR-0326). Maintained by upsert_deferred_pdu and
    // remove_deferred_pdu; read through take_deferred_pdus_awaiting.
    DeferredPduAwaits deferred_pdu_awaits{};
    // The state-group tables (ADR-0064) with their hash indexes (ADR-0325). Read-only through the
    // tables; every change goes through them, so a writer cannot leave an index behind. Lookups:
    // `event_state_groups.state_group_of(event_id)`, `state_groups.find(id)`,
    // `state_group_state.entries_of(id)`; see StateGroupTableSupport.hpp for the reader discipline.
    StateGroupTable state_groups{};
    StateGroupEntryTable state_group_state{};
    EventStateGroupTable event_state_groups{};
    std::vector<PersistentForwardExtremity> forward_extremities{};
    // Test-only capture of committed statements (AUTH-11). Empty and disabled
    // (`statement_capture_capacity == 0`) unless `enable_statement_capture` is
    // called, so production retains no statement or bound parameter after it
    // commits. When enabled it holds at most `statement_capture_capacity` of the
    // most recent statements; the oldest is dropped first. A vector, not a deque, so that
    // PersistentStore's noexcept moves cannot throw (ADR-0519); tests index it by position.
    std::vector<PreparedStatement> captured_statements{};
    std::size_t statement_capture_capacity{0U};
    // Transactions `commit_persistent_transaction` committed over the store's life, guarded by
    // `statement_capture_mutex` (read it through `committed_transaction_count`). A test reads the difference to
    // prove that an event's rows share one commit, not one commit each (ADR-0440, ADR-0441).
    std::uint64_t committed_transactions{0U};
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
    // stripe locks because capture access is independent of any room. Held by
    // value (ADR-0517) so PersistentStore stays copyable and moveable; a copy gets its own mutex.
    core::CopyableMutex statement_capture_mutex{};
    // DB-7, ADR-0154: persisted writes reuse at most this many connections
    // (database.pool_size, applied by set_write_connection_limit), instead of
    // opening one per transaction. The pool of the store's backend is created
    // when the store is opened; copies share it.
    std::uint32_t write_connection_limit{16U};
    std::shared_ptr<detail::SqliteWritePool> sqlite_write_pool{}; // SHARED_PTR: reviewed - shared by store copies.
    std::shared_ptr<detail::PostgresqlWritePool>                  // SHARED_PTR: reviewed - shared by store copies.
        postgresql_write_pool{};
    // Guards server_signing_keys. The remote-key resolver stores and reads
    // keys from federation relay threads and from backfill, both with the
    // runtime mutex released, so after start-up hydration every access goes
    // through store_server_signing_key, find_server_signing_key or
    // snapshot_server_signing_keys, which take this lock. It is never held
    // across a database write or a network call. Held by value (ADR-0517) so
    // PersistentStore stays copyable and moveable; a copy gets its own mutex.
    core::CopyableMutex server_signing_keys_mutex{};
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
    // ADR-0592: the stream token epoch, persisted to the stream_token_epoch singleton. Every sync token this
    // server issues carries it, and a token carrying another epoch was issued against other contents of the
    // database (before a restore, or by a database since replaced), so its positions mean nothing here. Zero
    // until the main process sets one at startup (homeserver::ensure_stream_token_epoch); the federation worker
    // never loads it.
    std::uint64_t stream_token_epoch{0U};
    // CSAZ-10: per-recipient to-device queue limits, copied from
    // server.client_api at runtime startup so the database layer can enforce
    // them without depending on the config module. A cap of zero disables the
    // bound (not recommended); a TTL of zero disables age-based eviction.
    std::uint32_t max_to_device_messages_per_user_device{10000U};
    std::uint32_t to_device_message_ttl_seconds{604800U};
    // Security audit run-2 F-14 (ADR-0335): the queue is bounded in bytes as well as rows. A message
    // whose content is over `max_to_device_message_bytes` is refused (the client path answers 413
    // M_TOO_LARGE, an inbound EDU drops that one message), and a recipient whose queued bytes would pass
    // `max_to_device_bytes_per_user_device` loses its oldest rows to make room. Zero disables a bound.
    std::uint32_t max_to_device_message_bytes{65536U};
    std::uint32_t max_to_device_bytes_per_user_device{16777216U};
    // Rows an enqueue or a drain looked at, summed over the store's life. A test reads the difference to
    // prove that a batch of M messages costs one pass over the queue, not one per message (F-13).
    std::uint64_t to_device_rows_examined{0U};
};

static_assert(std::is_nothrow_move_constructible_v<PersistentStore> &&
              std::is_nothrow_move_assignable_v<PersistentStore>);

// Serialise a token expiry time_point to its TEXT column form (epoch-ms decimal
// string, empty for no expiry) and parse it back. Shared by the INSERT paths and
// the SQLite/PostgreSQL store hydration so the encoding stays consistent.
[[nodiscard]] auto expires_at_text(std::optional<std::chrono::system_clock::time_point> const& expires_at)
    -> std::string;
[[nodiscard]] auto parse_expires_at(std::string_view text) -> std::optional<std::chrono::system_clock::time_point>;

[[nodiscard]] auto open_persistent_store(SchemaState existing_state = {}) -> PersistentStoreOpenResult;
[[nodiscard]] auto open_sqlite_persistent_store(std::string const& path,
                                                TableLoadProfile profile = TableLoadProfile::full)
    -> PersistentStoreOpenResult;
// Creates the SQLite database at `path` if it holds no tables, then migrates its
// schema forward to exactly `target_version` and stops: no rows are hydrated and
// nothing past that version is applied. It builds a database as an older release
// left it, so the upgrade path can be tested (ADR-0216); the next
// open_sqlite_persistent_store takes it the rest of the way. Refuses a target this
// build does not know (0 or above current_schema_version()) before opening the
// file, and a schema already past the target, since migrations never run
// backwards. On success `state` is the schema as read back from the database.
[[nodiscard]] auto migrate_sqlite_schema_to(std::string const& path, std::uint32_t target_version)
    -> MigrationApplyResult;
[[nodiscard]] auto validate_persistent_store(PersistentStore const& store) -> MigrationValidationResult;
[[nodiscard]] auto commit_persistent_transaction(PersistentStore& store,
                                                 std::vector<PreparedStatement> const& statements) -> bool;
// DB-7, ADR-0154: caps the connections persisted writes keep and use at once
// (database.pool_size). A write waits for a free connection rather than opening
// another. Takes effect for the next write.
auto set_write_connection_limit(PersistentStore& store, std::uint32_t limit) -> void;
// Connections ever opened for persisted writes (both backends' pools).
[[nodiscard]] auto write_connections_opened(PersistentStore const& store) -> std::uint64_t;
[[nodiscard]] auto store_user(PersistentStore& store, PersistentUser user) -> bool;
// P13 (ADR-0491): the account and its empty profile row in ONE transaction, so a registration commits once and
// cannot leave an account without a profile. False (nothing stored) when the user exists or the write fails.
[[nodiscard]] auto store_user_with_profile(PersistentStore& store, PersistentUser user, PersistentProfile profile)
    -> bool;
// P13 (ADR-0491): everything a logout revokes in ONE transaction: the presented access token, the device's refresh
// tokens and the device's access tokens. False (nothing revoked, in the database or in memory) when the write
// fails; true means all three are durable. A revocation is one-way (ADR-0052), so committing them together can
// only make a failed logout retryable from the start, never leave one token alive beside a revoked sibling.
[[nodiscard]] auto revoke_device_credentials(PersistentStore& store, std::string_view access_token_hash,
                                             std::string_view user_id, std::string_view device_id) -> bool;
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
// One transaction: the device row when `device` is set, the access token, and, with `replace_device_credentials`, the
// DELETE of every earlier access and refresh row of the token's (user, device) first (F-08, ADR-0590: a login on a
// device the user holds replaces its credentials; deleted, not revoked, because a presented revoked refresh row counts
// as reuse). Memory changes only after the commit; a failed commit changes nothing.
[[nodiscard]] auto store_device_and_access_token(PersistentStore& store, std::optional<PersistentDevice> device,
                                                 PersistentAccessToken token, bool replace_device_credentials = false)
    -> bool;
// A refresh rotation's writes in one transaction (F-08, ADR-0590): every earlier access row of the device is deleted,
// the new access and refresh rows are inserted, and `evicted_refresh_hashes` (rows the caller found retired, from
// `CredentialTable::oldest_retired_beyond`) are deleted. False, with nothing changed, if a named row is not retired.
[[nodiscard]] auto rotate_device_credentials(PersistentStore& store, PersistentAccessToken access,
                                             PersistentRefreshToken refresh,
                                             std::span<std::string const> evicted_refresh_hashes) -> bool;
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
// Upserts a signing key. Retirement (`expired_ts` != 0, a key a remote listed under old_verify_keys) is one
// way and the earliest expiry wins: a row already retired stays retired whatever a later write says, keeps
// its public key and takes the smaller of the two expiries; a current row written with an expiry becomes
// retired at once, with `valid_until_ts` set to it. A row that holds a secret (this server's own key) never
// takes an expiry: such a write returns false and changes nothing.
[[nodiscard]] auto store_server_signing_key(PersistentStore& store, PersistentServerSigningKey key) -> bool;
[[nodiscard]] auto find_server_signing_key(PersistentStore const& store, std::string_view server_name,
                                           std::string_view key_id) -> std::optional<PersistentServerSigningKey>;
// A copy of every stored signing key, taken under server_signing_keys_mutex.
// Callers that iterate the keys use this rather than the vector itself.
[[nodiscard]] auto snapshot_server_signing_keys(PersistentStore const& store)
    -> std::vector<PersistentServerSigningKey>;
// Re-reads `server_name`'s signing-key rows from the backing database into this
// store's in-memory mirror, public columns only: `secret_key` is never selected,
// so a federation worker (whose mirror is otherwise a snapshot taken when it
// started) can see a key main verified and cached since, without ever reading
// this server's signing secret. A row already held with a secret is left as it
// is. A successful no-op for an in-memory store. Returns false only on a
// connection or query failure, which leaves the mirror unchanged.
[[nodiscard]] auto refresh_remote_signing_keys(PersistentStore& store, std::string_view server_name) -> bool;
[[nodiscard]] auto store_federation_destination(PersistentStore& store, PersistentFederationDestination destination)
    -> bool;
[[nodiscard]] auto store_federation_transaction(PersistentStore& store, PersistentFederationTransaction transaction)
    -> bool;
// Upserts every transaction in one commit (ADR-0441): all are durable together or none is, and the mirror changes
// only after the commit. Returns false, writing nothing, if any is malformed or the commit fails.
[[nodiscard]] auto store_federation_transactions(PersistentStore& store,
                                                 std::vector<PersistentFederationTransaction> transactions) -> bool;
// Brings `federation_transaction_index` in step with `federation_transactions`.
auto rebuild_federation_transaction_index(PersistentStore& store) -> void;
[[nodiscard]] auto delete_federation_transaction(PersistentStore& store, std::string_view transaction_id) -> bool;

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
// the room's state groups with their entries and its events' state-group
// mappings, and the event relation tables scoped to that room's events) from the
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
// reload_room in its two halves (F-27, ADR-0358). `load_room_snapshot` is the database read: it
// does not touch `store`'s rows, so a caller runs it with no lock held. `apply_room_snapshot` is
// the in-memory swap: it replaces the room's rows with the snapshot's and needs exclusion from
// every reader of the store, which is all a reader then waits for. nullopt from the load is the
// connection/query failure reload_room reports as false; apply it never.
[[nodiscard]] auto load_room_snapshot(PersistentStore const& store, std::string_view room_id)
    -> std::optional<RoomReloadSnapshot>;
auto apply_room_snapshot(PersistentStore& store, RoomReloadSnapshot snapshot) -> void;
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

// The statements that make `state` current, replacing `previous_event_id`
// (empty for a key with no current_state row yet), and record the transition.
// Does not check that `state` names a stored event: see
// state_matches_stored_event.
[[nodiscard]] auto prepare_current_state(PersistentStateEvent state, std::string previous_event_id)
    -> PreparedCurrentState;
// Mirrors a committed prepare_current_state into current_state and the
// state_transitions index.
auto apply_current_state(PersistentStore& store, PreparedCurrentState const& prepared) -> void;
// True when `state` names a stored event of that type and state key in that room.
[[nodiscard]] auto state_matches_stored_event(PersistentStore const& store, PersistentStateEvent const& state) -> bool;
// With `membership`, also writes that membership row and invite change in the same
// transaction (DB-4). The projection must name the state event's own user: `state`
// must be the m.room.member entry whose state_key is `membership->user_id`, or
// nothing is stored.
[[nodiscard]] auto store_event_with_state(PersistentStore& store, PersistentEvent event,
                                          std::optional<PersistentStateEvent> state,
                                          std::optional<MembershipProjection> membership = std::nullopt) -> bool;
// DB-4: writes a membership row and its invite change in one transaction, for a
// membership change this server records without storing an event of its own (a
// federated leave, an invite received over /invite for a room whose state it
// holds). The in-memory mirror changes only after the commit.
[[nodiscard]] auto store_membership_projection(PersistentStore& store, std::string_view room_id,
                                               MembershipProjection projection) -> bool;
// DB-4: makes each `membership` row agree with its room's current m.room.member
// state event, which is the user's membership (Matrix v1.19 "m.room.member").
// A row is rewritten to the event's membership when the row is missing, when it
// says "join" and the event does not (a row never grants more than current
// state), or when the event is newer than the row (higher stream_ordering). A
// row newer than the event is kept: it is a change recorded here before its
// event arrived (a federated leave, an /invite). Rewritten rows take a fresh
// stream ordering from `allocate_stream_ordering` so incremental /sync sees the
// change, and "join"/"leave"/"ban" drop the user's invite metadata, all in one
// transaction. The in-memory rows are corrected even when that commit fails —
// they then match current_state, which is already durable — and the next
// startup retries the write. Returns the number of rows corrected.
[[nodiscard]] auto reconcile_memberships_with_current_state(
    PersistentStore& store, std::function<std::uint64_t()> const& allocate_stream_ordering) -> std::size_t;

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

// create_or_reuse_state_group without the commit. A parent, when given, must
// already be in the store. Returns nullopt when it is not a valid group.
[[nodiscard]] auto prepare_state_group(PersistentStore const& store, std::string_view room_id,
                                       std::string_view new_state_group_id,
                                       std::optional<std::string> const& parent_state_group_id,
                                       std::vector<PersistentStateGroupStateEntry> const& full_state)
    -> std::optional<PreparedStateGroup>;
// Mirrors a committed prepare_state_group into the in-memory store.
auto apply_state_group(PersistentStore& store, PreparedStateGroup const& prepared) -> void;

// Returns `state_group_id`'s own row (its room, parent, and delta depth —
// not its resulting state; see read_state_group_full_state for that), or
// nullopt if no such group exists.
[[nodiscard]] auto find_state_group(PersistentStore const& store, std::string_view state_group_id)
    -> std::optional<PersistentStateGroup>;

// The event ID `state_group_id`'s full resulting state holds for (event_type, state_key), walking the
// delta chain newest first, bounded and cycle-checked as read_state_group_full_state is. nullopt when
// the chain is broken (a group missing, a cycle, too deep); an empty view when the chain is sound and
// the state has no such key. The view points into the store, so it lives as long as the row does.
[[nodiscard]] auto find_state_group_state_event_id(PersistentStore const& store, std::string_view state_group_id,
                                                   std::string_view event_type, std::string_view state_key)
    -> std::optional<std::string_view>;

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
// set_event_state_group's statement, uncommitted (ADR-0228); nullopt for an
// empty `event_id` or `state_group_id`.
[[nodiscard]] auto prepare_event_state_group(std::string_view event_id, std::string_view state_group_id)
    -> std::optional<PreparedStatement>;
// Mirrors a committed prepare_event_state_group into the in-memory mapping.
auto apply_event_state_group(PersistentStore& store, std::string_view event_id, std::string_view state_group_id)
    -> void;
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
// update_forward_extremities for an accepted event, uncommitted (ADR-0228):
// the statements that remove `replaced_event_ids` from `room_id`'s
// extremities and add `event_id`. Empty for an empty `room_id` or `event_id`.
[[nodiscard]] auto prepare_forward_extremities_update(std::string_view room_id, std::string_view event_id,
                                                      std::vector<std::string> const& replaced_event_ids)
    -> std::vector<PreparedStatement>;
// Mirrors a committed prepare_forward_extremities_update in memory.
auto apply_forward_extremities_update(PersistentStore& store, std::string_view room_id, std::string_view event_id,
                                      std::vector<std::string> const& replaced_event_ids) -> void;
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

// The event ID of the current state event for (room_id, event_type, state_key), or nullopt when the
// room has none. An index lookup (ADR-0344): no scan of `state` while the index is in step with it.
[[nodiscard]] auto find_current_state_event_id(PersistentStore const& store, std::string_view room_id,
                                               std::string_view event_type, std::string_view state_key)
    -> std::optional<std::string>;

// Calls `visit` with every row of `state` that belongs to `room_id`, in storage order. Walks only
// that room's rows while the index is in step with `state` (ADR-0344). `visit` must not change `state`.
auto for_each_room_state_row(PersistentStore const& store, std::string_view room_id,
                             std::function<void(PersistentStateEvent const&)> const& visit) -> void;

// Rebuilds the in-memory state indexes from `state`. Called after SQLite/PostgreSQL hydration,
// after `reload_room` and after any direct edit of the vector that should be fast again.
auto rebuild_state_index(PersistentStore& store) -> void;

// Calls `visit` with every row of `memberships` that belongs to `room_id`, in storage order. Walks only that
// room's rows while the index is in step with `memberships` (ADR-0437). `visit` must not change `memberships`.
auto for_each_room_membership_row(PersistentStore const& store, std::string_view room_id,
                                  std::function<void(PersistentMembership const&)> const& visit) -> void;

// Rebuilds the per-room membership index from `memberships`. Called after SQLite/PostgreSQL hydration,
// after `reload_room`, after a row is erased, and after any direct edit of the vector that should be fast again.
auto rebuild_membership_index(PersistentStore& store) -> void;

// Rebuilds the in-memory client transaction indexes from `client_txn_ids`. Called after
// SQLite/PostgreSQL hydration.
auto rebuild_client_txn_index(PersistentStore& store) -> void;

// Deletes the to-device transaction records (room_id empty) made before `cutoff_ms`, from the database in
// one statement and then from `client_txn_ids`, and rebuilds both indexes (they hold positions in the
// vector). Room-send and redact records are never touched. Returns the number removed; on a failed
// write nothing is removed and it returns 0. One pass over the vector, so a caller that holds
// runtime.mutex runs it from a periodic job, not from a request (F-54, ADR-0381). A request retried
// after its record is gone is processed again, which is accepted.
[[nodiscard]] auto prune_to_device_client_txns(PersistentStore& store, std::uint64_t cutoff_ms) -> std::size_t;

// How long a to-device transaction record is kept: 7 days (ADR-0381).
inline constexpr std::uint64_t to_device_client_txn_retention_ms = 7ULL * 24ULL * 60ULL * 60ULL * 1000ULL;

// The record of the room send that produced `event_id`, or nullptr (also for an empty ID). An
// index lookup; the sender, device and transaction ID are the record's.
[[nodiscard]] auto find_client_txn_by_event_id(PersistentStore const& store, std::string_view event_id)
    -> PersistentClientTxnRecord const*;

// ---- CSAZ-11: redactions ----
//
// Rebuilds `store.redactions` from `store.events`: every m.room.redaction event is withheld
// until the redaction reconciler applies it. Called after hydration.
auto rebuild_redaction_state(PersistentStore& store) -> void;
// IDs of the redaction events that name `target_event_id`, in the order they were stored.
[[nodiscard]] auto redactions_naming(PersistentStore const& store, std::string_view target_event_id)
    -> std::vector<std::string>;
// True when `event_id` is a redaction event that has not been applied, so clients must not be
// sent it. False for every other event.
[[nodiscard]] auto redaction_is_withheld(PersistentStore const& store, std::string_view event_id) -> bool;
// The redaction event applied to `target_event_id`, if any.
[[nodiscard]] auto applied_redaction_of(PersistentStore const& store, std::string_view target_event_id)
    -> std::optional<std::string>;
// Records that `redaction_event_id` was applied to `target_event_id`: the redaction event is no
// longer withheld and `target_event_id` has a `redacted_because`.
auto mark_redaction_applied(PersistentStore& store, std::string_view redaction_event_id,
                            std::string_view target_event_id) -> void;
// Overwrites the stored JSON of an existing event (UPDATE, then the in-memory copy). This is how
// a redaction destroys the original content: only the redacted JSON is kept. Returns false if the
// event is unknown or the backend refuses the write.
[[nodiscard]] auto replace_event_json(PersistentStore& store, std::string_view event_id, std::string json) -> bool;

// Looks up a state transition by its primary tuple. Requires the index to be
// current; callers that modify the vector directly must call
// rebuild_state_transition_index() first.
[[nodiscard]] auto find_state_transition(PersistentStore const& store, std::string_view room_id,
                                         std::string_view event_type, std::string_view state_key,
                                         std::string_view event_id) -> PersistentStateTransition const*;

[[nodiscard]] auto prepare_store_event_with_state(PersistentStore& store, PersistentEvent event,
                                                  std::optional<PersistentStateEvent> state,
                                                  std::optional<MembershipProjection> membership = std::nullopt)
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
// Removes the alias. False when it does not exist or the backend refuses.
[[nodiscard]] auto delete_room_alias(PersistentStore& store, std::string_view room_alias) -> bool;
// Points the alias at `new_room_id` in one statement, keeping its creator. False when the alias does not exist,
// `new_room_id` names no room, or the backend refuses; the alias then still names its old room.
[[nodiscard]] auto reassign_room_alias(PersistentStore& store, std::string_view room_alias,
                                       std::string_view new_room_id) -> bool;
[[nodiscard]] auto store_device_key(PersistentStore& store, PersistentDeviceKey key) -> bool;
[[nodiscard]] auto find_device_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id)
    -> std::optional<PersistentDeviceKey>;
[[nodiscard]] auto store_one_time_key(PersistentStore& store, PersistentOneTimeKey key) -> bool;
[[nodiscard]] auto claim_one_time_key(PersistentStore& store, std::string_view user_id, std::string_view device_id,
                                      std::string_view algorithm = {}) -> std::optional<PersistentOneTimeKey>;
// The algorithm part of a fallback key ID: up to and including its first ':', or the whole ID when it has none. A
// device holds one fallback key per value of this; store_fallback_key replaces by it and the upload cap counts it
// (GHSA-3p9g-gpvx-2cx9, ADR-0594), so both must use this one function.
[[nodiscard]] auto fallback_key_algorithm(std::string_view key_id) noexcept -> std::string_view;
[[nodiscard]] auto store_fallback_key(PersistentStore& store, PersistentFallbackKey key) -> bool;
[[nodiscard]] auto find_fallback_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id,
                                     std::string_view algorithm = {}) -> std::optional<PersistentFallbackKey>;
// Lookups by index (ADR-0603). Each reads the index while it is in step with its vector and scans the vector
// otherwise, and counts the rows it read in the matching `*_rows_examined`.
// True when this server holds any membership row for the room, in any state.
[[nodiscard]] auto has_room_membership_row(PersistentStore const& store, std::string_view room_id) -> bool;
// The user's membership row for the room, or nullptr.
[[nodiscard]] auto find_membership_row(PersistentStore const& store, std::string_view room_id, std::string_view user_id)
    -> PersistentMembership const*;
// The account row for the user, or nullptr.
[[nodiscard]] auto find_user_row(PersistentStore const& store, std::string_view user_id) -> PersistentUser const*;
// Calls `visit` with each of the user's device rows; stops when it returns false.
auto for_each_user_device(PersistentStore const& store, std::string_view user_id,
                          std::function<bool(PersistentDevice const&)> const& visit) -> void;
// Calls `visit` with each of the user's cross-signing key rows; stops when it returns false.
auto for_each_user_cross_signing_key(PersistentStore const& store, std::string_view user_id,
                                     std::function<bool(PersistentCrossSigningKey const&)> const& visit) -> void;
// Calls `visit` with each of the user's published device-key rows; stops when it returns false.
auto for_each_user_device_key(PersistentStore const& store, std::string_view user_id,
                              std::function<bool(PersistentDeviceKey const&)> const& visit) -> void;
// Rebuilds the user, device, device-key, one-time-key, fallback-key and key backup indexes from their vectors.
// Called after SQLite/PostgreSQL hydration and by a writer that finds one stale.
auto rebuild_key_indexes(PersistentStore& store) -> void;
// Key backup reads by index (ADR-0606). The version of a user that was created last is their current one.
[[nodiscard]] auto find_key_backup_version(PersistentStore const& store, std::string_view user_id,
                                           std::string_view version) -> PersistentKeyBackupVersion const*;
[[nodiscard]] auto latest_key_backup_version(PersistentStore const& store, std::string_view user_id)
    -> PersistentKeyBackupVersion const*;
[[nodiscard]] auto count_key_backup_versions(PersistentStore const& store, std::string_view user_id) -> std::size_t;
// Sessions held for one backup version, and for all of a user's versions.
[[nodiscard]] auto count_key_backup_sessions(PersistentStore const& store, std::string_view user_id,
                                             std::string_view version) -> std::size_t;
[[nodiscard]] auto count_user_key_backup_sessions(PersistentStore const& store, std::string_view user_id)
    -> std::size_t;
[[nodiscard]] auto find_key_backup_session(PersistentStore const& store, std::string_view user_id,
                                           std::string_view version, std::string_view room_id,
                                           std::string_view session_id) -> PersistentKeyBackupSession const*;
// Calls `visit` with each session of the backup. The order is not meaningful.
auto for_each_key_backup_session(PersistentStore const& store, std::string_view user_id, std::string_view version,
                                 std::function<void(PersistentKeyBackupSession const&)> const& visit) -> void;
[[nodiscard]] auto store_cross_signing_key(PersistentStore& store, PersistentCrossSigningKey key) -> bool;
// Stores every key in one transaction: all are written or, when the write fails or a key is refused,
// none is and the held keys are unchanged. An empty list succeeds and writes nothing.
[[nodiscard]] auto store_cross_signing_keys(PersistentStore& store, std::vector<PersistentCrossSigningKey> keys)
    -> bool;
[[nodiscard]] auto store_key_signature(PersistentStore& store, PersistentKeySignature signature) -> bool;
// Every uploaded signature whose target is `target_user_id`, in storage order.
// Backed by the target index (CSAZ-10); falls back to a scan only when the
// index is out of step with the rows. References are valid until the next
// mutation of `store.key_signatures`.
[[nodiscard]] auto key_signatures_for_target(PersistentStore const& store, std::string_view target_user_id)
    -> std::vector<std::reference_wrapper<PersistentKeySignature const>>;
// Rebuilds the target index from `key_signatures`. Called after SQLite and
// PostgreSQL hydration and after any direct fill of the vector.
auto rebuild_key_signature_index(PersistentStore& store) -> void;
[[nodiscard]] auto store_key_backup_version(PersistentStore& store, PersistentKeyBackupVersion version) -> bool;
// Creates a new backup version for `user_id` and returns its number (decimal, 1 for the first). The number
// is one past the highest ever issued to the user (`key_backup_version_high_water`) and past every numeric
// version still held, so a number is never issued twice, even after the version holding it was deleted. The
// counter and the version row are written in ONE transaction. nullopt for an invalid payload or a failed
// write, with nothing changed (F-60, ADR-0384).
[[nodiscard]] auto create_key_backup_version(PersistentStore& store, std::string_view user_id, std::string json)
    -> std::optional<std::string>;
// Deletes the version and every session uploaded to it in ONE transaction, then both from memory (F-60).
// A version that is not held succeeds without touching anything.
[[nodiscard]] auto delete_key_backup_version(PersistentStore& store, std::string_view user_id, std::string_view version)
    -> bool;
[[nodiscard]] auto store_key_backup_session(PersistentStore& store, PersistentKeyBackupSession session) -> bool;
// Stores every session in one transaction: all are written or, when the write fails or a session is
// refused, none is. An empty list succeeds and writes nothing.
[[nodiscard]] auto store_key_backup_sessions(PersistentStore& store, std::vector<PersistentKeyBackupSession> sessions)
    -> bool;
[[nodiscard]] auto delete_key_backup_room_sessions(PersistentStore& store, std::string_view user_id,
                                                   std::string_view version, std::string_view room_id) -> bool;
[[nodiscard]] auto delete_key_backup_session(PersistentStore& store, std::string_view user_id, std::string_view version,
                                             std::string_view room_id, std::string_view session_id) -> bool;
[[nodiscard]] auto delete_all_key_backup_sessions(PersistentStore& store, std::string_view user_id,
                                                  std::string_view version) -> bool;
[[nodiscard]] auto store_local_media(PersistentStore& store, PersistentLocalMedia media) -> bool;
// DB-5: writes a new upload's media row and its blob (inserted, or updated with the
// new reference count when deduplicated) in one transaction. The in-memory mirror
// changes only after the commit succeeds; on failure nothing is written.
// When `new_blob` is true the blob row is written with `blob.bytes` (a new
// blob, or a removed one revived by a re-upload); otherwise the bytes are
// already durable and only the reference count is updated (ADR-0119).
// `completes_pending_media_id`, when not empty, names the pending reservation
// (POST /_matrix/media/v1/create) this upload fills; its row is deleted in the
// same transaction (ADR-0212).
[[nodiscard]] auto commit_local_media_upload(PersistentStore& store, PersistentLocalMedia media,
                                             PersistentMediaBlob const& blob, bool new_blob,
                                             std::string_view completes_pending_media_id = {}) -> bool;
// F-16: the most expired reservations one commit_pending_media_upload deletes. A longer list is refused.
inline constexpr std::size_t max_pending_media_deleted_per_commit{256U};
// ADR-0212: inserts one pending upload reservation and deletes the expired
// reservations in `expired_media_ids` (at most max_pending_media_deleted_per_commit)
// with DELETE statements of up to 128 IDs, in one transaction. The in-memory mirror changes only after the
// commit succeeds, in one pass over the reservations with hash-set membership.
[[nodiscard]] auto commit_pending_media_upload(PersistentStore& store, PersistentPendingMediaUpload row,
                                               std::vector<std::string> const& expired_media_ids) -> bool;

[[nodiscard]] auto prepare_media_blob_read(PersistentStore const& store, std::string_view storage_id) -> MediaBlobRead;
// The blob's bytes, or nullopt when it is not referenced or cannot be read.
[[nodiscard]] auto read_media_blob(MediaBlobRead const& read) -> std::optional<std::string>;

// ADR-0574: reads `length` bytes at `offset` of a blob that must still be referenced and exactly `expected_size`
// bytes long, on a connection that is closed before this returns. nullopt on any mismatch or failure.
[[nodiscard]] auto read_media_blob_chunk(MediaBlobRead const& read, std::uint64_t expected_size, std::uint64_t offset,
                                         std::size_t length) -> std::optional<std::string>;
[[nodiscard]] auto update_local_media_state(PersistentStore& store, std::string_view media_id, bool quarantined,
                                            bool removed) -> bool;
// Commit moderation metadata, optional blob removal and both audit records
// together. Repository projections must be changed only after this succeeds.
[[nodiscard]] auto commit_local_media_moderation(PersistentStore& store, std::string_view media_id, bool quarantined,
                                                 bool removed, PersistentAdminAction action, PersistentAuditEvent audit)
    -> bool;
[[nodiscard]] auto store_remote_media(PersistentStore& store, PersistentRemoteMedia media) -> bool;
// ADR-0119: admits fetched remote media in one transaction. Deletes the media
// and cache rows of `releases`, sets each of `released_blobs` to its new
// reference count (clearing the bytes at zero), inserts `media`, writes `blob`
// (its bytes when `new_blob`, otherwise only its reference count, which must
// already account for `releases`), and upserts `mapping`. The in-memory
// mirror changes only after the commit succeeds.
[[nodiscard]] auto commit_remote_media_admission(PersistentStore& store, PersistentLocalMedia media,
                                                 PersistentMediaBlob const& blob, bool new_blob,
                                                 PersistentRemoteMedia mapping,
                                                 std::vector<PersistentRemoteMediaRelease> const& releases,
                                                 std::vector<PersistentBlobReferenceCount> const& released_blobs)
    -> bool;
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
// Security audit run-2 F-12 (ADR-0339): the most bytes of content one account-data row may hold.
// store_account_data and both capped forms refuse a row over it, so rows the server writes itself
// (m.tag) are bounded by the same limit as a client's PUT. Every /sync parses each row into a DOM
// under runtime.mutex, and a read-modify-write row such as m.tag grows past any one request body.
inline constexpr std::size_t max_account_data_row_bytes{262144U};

// Returns false, writing nothing, for a missing user or type, content over
// `max_account_data_row_bytes`, or a failed write.
[[nodiscard]] auto store_account_data(PersistentStore& store, PersistentAccountData data) -> bool;
// Brings `account_data_user_index` in step with `account_data`. Hydration calls it; the writers keep it so.
auto rebuild_account_data_index(PersistentStore& store) -> void;
// Visits the rows of `user_id` only (ADR-0440): through the index while it is in step, else by scan. Adds the rows
// it looked at to `store.account_data_rows_examined`.
auto for_each_user_account_data(PersistentStore const& store, std::string_view user_id,
                                std::function<void(PersistentAccountData const&)> const& visit) -> void;
// The content of the row (user_id, room_id, event_type), or nullopt. Looks at the user's rows only.
[[nodiscard]] auto find_account_data_content(PersistentStore const& store, std::string_view user_id,
                                             std::string_view room_id, std::string_view event_type)
    -> std::optional<std::string>;

// Stores a global (room_id empty) account-data row unless it would give the user more than
// `max_global_types` distinct global types (ADR-0173). A type the user already holds is always
// updated. One pass over the in-memory rows both counts the user's types and finds the row to
// update, because the PUT path runs under runtime.mutex. A refusal writes nothing and allocates
// no sync stream position.
[[nodiscard]] auto store_global_account_data_within_cap(PersistentStore& store, PersistentAccountData data,
                                                        std::size_t max_global_types) -> CappedAccountDataStore;
// Stores a room account-data row (room_id set) unless it would give the user more than
// `max_room_types` distinct types in that room (ADR-0197). Same contract as the global form: a
// type the user already holds in the room is always updated, one pass under runtime.mutex, and a
// refusal writes nothing. Rows the server writes through store_account_data (m.tag,
// m.fully_read) are counted but never refused.
[[nodiscard]] auto store_room_account_data_within_cap(PersistentStore& store, PersistentAccountData data,
                                                      std::size_t max_room_types) -> CappedAccountDataStore;
// Sets the receipt `receipt` names by (room_id, receipt_type, user_id,
// thread_id) to its event_id and ts, at a newly allocated sync stream
// position written back into the stored row. The row is committed before the
// in-memory mirror changes. An optional eviction is deleted in the same
// transaction as the upsert. Returns false on a backend failure or an empty
// key field or an event_id or thread_id over 255 bytes, without changing the mirror; allocated
// stream IDs are never reused.
[[nodiscard]] auto store_receipt(PersistentStore& store, PersistentReceipt receipt,
                                 std::optional<PersistentReceipt> evicted = std::nullopt) -> bool;
// Removes the receipt with `receipt`'s key. False if there was none or the
// delete could not be committed.
[[nodiscard]] auto remove_receipt(PersistentStore& store, PersistentReceipt const& receipt) -> bool;
[[nodiscard]] auto enqueue_to_device_message(PersistentStore& store, PersistentToDeviceMessage message) -> bool;
// Queues every message, with the per-recipient age and count evictions of
// `enqueue_to_device_message`, in ONE backend transaction: either all of them
// are durable and mirrored in memory, or none are and the store is unchanged
// (stream ids are consumed, never reused). An inbound `m.direct_to_device` EDU
// uses it so a failed commit never leaves the EDU partly stored. An empty
// `messages` writes nothing and returns true; an invalid message returns false
// with nothing written.
[[nodiscard]] auto enqueue_to_device_messages(PersistentStore& store, std::vector<PersistentToDeviceMessage> messages)
    -> bool;
// R02: queues every message (with the per-recipient age and count evictions of
// `enqueue_to_device_message`) and records `record` as the client's
// send-to-device transaction in ONE backend transaction. Either all of it is
// durable and mirrored in memory, or none of it is and the store is unchanged
// (stream ids are consumed, never reused), so a failed request leaves the
// client free to retry the same transaction ID. An empty `messages` records the
// transaction alone. Returns true without writing when the transaction is
// already recorded: the request that recorded it committed its messages with
// it. Returns false for an invalid message or record, or a failed commit.
[[nodiscard]] auto enqueue_to_device_messages_with_client_txn(PersistentStore& store,
                                                              std::vector<PersistentToDeviceMessage> messages,
                                                              PersistentClientTxnRecord record) -> bool;
// True when `content_json` is within `store.max_to_device_message_bytes` (F-14). The callers that take
// to-device content from a client or a remote server ask this before queueing it.
[[nodiscard]] auto to_device_content_fits(PersistentStore const& store, std::string_view content_json) noexcept -> bool;
// The bytes the queue holds for one (user, device): what the per-device byte bound counts (F-14). Computed
// from the rows, so it is right after any eviction, acknowledgement or hydration.
[[nodiscard]] auto to_device_queue_bytes(PersistentStore const& store, std::string_view user_id,
                                         std::string_view device_id) -> std::uint64_t;
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
// Replace only the extended fields (a canonical JSON object) of an existing profile row.
[[nodiscard]] auto update_profile_fields(PersistentStore& store, std::string_view user_id, std::string_view fields_json)
    -> bool;
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
// Upserts every notification in one transaction (ADR-0440) and prunes each notified user's oldest rows beyond
// `max_per_user` in that same transaction. All rows and prunes are durable together or none is, and the in-memory
// mirror changes only after the commit. Returns false, writing nothing, if any row has an empty user_id, room_id
// or event_id, or the commit fails. An empty batch succeeds and commits nothing.
[[nodiscard]] auto store_notifications(PersistentStore& store, std::vector<PersistentNotification> notifications,
                                       std::size_t max_per_user = 1000U) -> bool;
// Brings `notification_user_index` in step with `notifications`.
auto rebuild_notification_index(PersistentStore& store) -> void;
// Return every notification recorded for user_id, in insertion
// (stream_ordering) order ascending. Callers apply from/limit/only
// pagination and filtering.
[[nodiscard]] auto list_notifications_for_user(PersistentStore const& store, std::string_view user_id)
    -> std::vector<PersistentNotification>;
[[nodiscard]] auto collect_unusable_credentials(PersistentStore const& store, std::chrono::system_clock::time_point now,
                                                std::chrono::system_clock::duration expired_access_grace)
    -> UnusableCredentials;
// Deletes the named rows from the database in ONE transaction, so a caller bounds its batch by the size of the
// spans. Memory is untouched: pass what was deleted to `forget_credentials` once the whole sweep is done, which
// makes one pass over each vector instead of one per batch.
[[nodiscard]] auto delete_credential_rows(PersistentStore& store, std::span<std::string const> access_token_hashes,
                                          std::span<std::string const> refresh_token_hashes) -> bool;
auto forget_credentials(PersistentStore& store, UnusableCredentials const& deleted) -> void;
// ADR-0489: audit retention. `cutoff_ms` is Unix milliseconds; rows stamped 0 are never touched.
// Whether any durable row older than the cutoff exists (nullopt: the backend could not be read). Reads on a
// connection of its own, so a caller may hold no lock.
[[nodiscard]] auto audit_rows_older_than_exist(PersistentStore const& store, std::uint64_t cutoff_ms)
    -> std::optional<bool>;
// Deletes at most `limit` such rows in one transaction. False when the write failed.
[[nodiscard]] auto delete_audit_rows_older_than(PersistentStore& store, std::uint64_t cutoff_ms, std::size_t limit)
    -> bool;
// Drops the in-memory window's rows older than the cutoff and returns how many.
auto forget_audit_events_older_than(PersistentStore& store, std::uint64_t cutoff_ms) -> std::size_t;
// Insert an OpenID token row. Persists it, mirrors it into the in-memory
// vector, and then prunes every already-expired row (across all users) so
// `openid_tokens` cannot grow without bound -- the time-based analogue of
// store_notification's per-user count cap, appropriate here because an
// OpenID token's natural retention bound is its own short expiry rather
// than a row count. Returns false on an empty user_id/token_hash or a
// backend write failure.
[[nodiscard]] auto store_openid_token(PersistentStore& store, PersistentOpenidToken token) -> bool;
// Deletes every OpenID token row of `user_id`, from the backend and from the in-memory
// vector. Returns true when no row of the user remains (including when there never was
// one) and false on a backend write failure, which leaves the in-memory rows in place so
// the caller can retry. Unlike the access-token revocations, the answer is a bool: a
// zero count here is not ambiguous because the caller only needs "none left".
[[nodiscard]] auto revoke_openid_tokens_for_user(PersistentStore& store, std::string_view user_id) -> bool;
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
// Queues one event for one appservice. Idempotent on (appservice_id,
// stream_ordering): queueing a row that is already queued succeeds and changes
// nothing. False for an empty appservice_id or event_id, or a backend write
// failure (nothing is queued in memory then).
[[nodiscard]] auto enqueue_appservice_event(PersistentStore& store, PersistentAppserviceOutboxEntry entry) -> bool;
// Publishes (`listed`) or unpublishes a room in one network's directory of an appservice. Idempotent: listing
// a room already listed, or unlisting one that is not, succeeds and changes nothing. False for an empty
// identifier or a backend write failure (memory is unchanged then).
[[nodiscard]] auto set_appservice_directory_entry(PersistentStore& store, PersistentAppserviceDirectoryEntry entry,
                                                  bool listed) -> bool;
// True when `room_id` is listed in the directory of `network_id` of `appservice_id`.
[[nodiscard]] auto appservice_directory_contains(PersistentStore const& store, std::string_view appservice_id,
                                                 std::string_view network_id, std::string_view room_id) -> bool;
// How many rows are queued for `appservice_id` (ADR-0191: the per-appservice cap is checked
// against this). Two binary searches over the sorted outbox, so cheap enough to call per event.
[[nodiscard]] auto count_appservice_outbox_entries(PersistentStore const& store, std::string_view appservice_id)
    -> std::size_t;
// True when the row `(appservice_id, stream_ordering)` is already queued.
[[nodiscard]] auto has_appservice_outbox_entry(PersistentStore const& store, std::string_view appservice_id,
                                               std::uint64_t stream_ordering) -> bool;
// The queued row with the lowest stream_ordering for `appservice_id`, or
// nullopt when its queue is empty.
[[nodiscard]] auto find_first_appservice_outbox_entry(PersistentStore const& store, std::string_view appservice_id)
    -> std::optional<PersistentAppserviceOutboxEntry>;
// Puts the in-memory outbox back in (appservice_id, stream_ordering) order, the
// order every outbox function relies on. The backend loaders call it after
// hydrating the rows: ORDER BY on the TEXT columns is neither numeric nor,
// on PostgreSQL, byte-wise.
auto sort_appservice_outbox(PersistentStore& store) -> void;
// Puts the in-memory to-device queue back in numeric stream_id order. The
// column is TEXT, so ORDER BY puts "10" before "9" on both backends; the loaders
// call this after hydrating, and everything that pages through the queue relies
// on the order (a continuation position acknowledges every row at or below it).
auto sort_to_device_messages(PersistentStore& store) -> void;
// Records that the transaction carrying stream_ordering `delivered_stream_
// ordering` has been dealt with (acknowledged, vacuously acknowledged by a
// url:null appservice, or dropped as unreadable). In ONE backend transaction:
// clears the cursor's pending transaction, raises its delivered high-water mark
// to max(current, delivered_stream_ordering), and deletes the outbox row for
// that ordering if there is one. The in-memory mirrors change only after the
// commit succeeds, so a crash or a failure can never leave the cursor
// advanced with the row still queued (a duplicate) or the row gone with the
// cursor still pending (a stuck transaction).
[[nodiscard]] auto complete_appservice_delivery(PersistentStore& store, std::string_view appservice_id,
                                                std::uint64_t delivered_stream_ordering) -> bool;

// Retains `pdu`, or updates the row for its event_id. The row is committed to
// the backend before the in-memory mirror changes.
[[nodiscard]] auto upsert_deferred_pdu(PersistentStore& store, PersistentDeferredPdu pdu) -> DeferredPduUpsert;
// Removes the row for `event_id`. False if there was none or the delete could
// not be committed.
[[nodiscard]] auto remove_deferred_pdu(PersistentStore& store, std::string_view event_id) -> bool;
[[nodiscard]] auto find_missing_event_references(PersistentStore const& store,
                                                 std::vector<std::string> const& auth_event_ids,
                                                 std::vector<std::string> const& prev_event_ids)
    -> MissingEventReferences;
// The first of `event_ids` this store holds in a room other than `room_id`, or nullopt if none is. An
// event may only build on events of its own room (ADR-0583); one the store does not hold is not asked
// about here. One hash lookup per ID.
[[nodiscard]] auto find_event_in_other_room(PersistentStore const& store, std::string_view room_id,
                                            std::vector<std::string> const& event_ids) -> std::optional<std::string>;
// Rebuilds `store.deferred_pdu_awaits` from the retained rows, parsing each row's JSON once. Hydration
// calls it after every table is loaded.
auto rebuild_deferred_pdu_awaits(PersistentStore& store) -> void;
// The IDs of the retained PDUs of `room_id` that are waiting for `event_id`, other than `event_id`
// itself, found by lookup in the index (no row is searched). They stop waiting for it: a second call
// with the same ID finds none until a retained PDU is indexed under it again.
[[nodiscard]] auto take_deferred_pdus_awaiting(PersistentStore& store, std::string_view room_id,
                                               std::string_view event_id) -> std::vector<std::string>;
// Copies of the retained PDUs: every one, or one room's.
[[nodiscard]] auto list_deferred_pdus(PersistentStore const& store) -> std::vector<PersistentDeferredPdu>;
[[nodiscard]] auto deferred_pdus_for_room(PersistentStore const& store, std::string_view room_id)
    -> std::vector<PersistentDeferredPdu>;
// Look up a previous idempotent send result. Returns the stored event_id
// (or empty string for to-device sends) if the (user_id, device_id, room_id,
// event_type, txn_id) tuple was already committed; nullopt otherwise. A transaction ID is scoped to one
// device (client-server-api.md, "Transaction identifiers"), so the device is part of the key; a request
// with no device (an appservice token without a device) uses the empty device ID, which is its own scope.
[[nodiscard]] auto find_client_txn_event_id(PersistentStore const& store, std::string_view user_id,
                                            std::string_view device_id, std::string_view room_id,
                                            std::string_view event_type, std::string_view txn_id)
    -> std::optional<std::string>;
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
// cannot roll the counter backward behind a client's since-token. Throws
// std::overflow_error, leaving the counter unchanged, rather than pass
// INT64_MAX (ADR-0315). A failed watermark write is logged at error level, not thrown, and the id is
// still issued: the next successful write records the counter past it (ADR-0540). Nothing else moves the
// counter upward, client input least of all.
// ADR-0315: writes that a sync position must follow stop this far below the counter's ceiling. Far more
// positions than one request takes, and the margin covers requests between this check and their allocation.
inline constexpr auto sync_stream_write_reserve = std::uint64_t{1U} << 20U;

// False, and logged, once the counter is inside that reserve. Changes nothing.
[[nodiscard]] auto sync_stream_has_write_reserve(PersistentStore const& store) -> bool;

[[nodiscard]] auto allocate_sync_stream_id(PersistentStore& store) -> std::uint64_t;
// Persists `watermark` (the highest allocated timeline stream_ordering) to
// the `event_stream_watermark` singleton and mirrors it into
// `store.event_stream_watermark`. Every stream_ordering allocation must
// record its value here so a restart cannot roll the timeline counter
// backward behind a pos/since token a client already holds.
[[nodiscard]] auto persist_event_stream_watermark(PersistentStore& store, std::uint64_t watermark) -> bool;
// ADR-0592: writes `epoch` to the `stream_token_epoch` singleton and, only once that write succeeded, to
// `store.stream_token_epoch`. Refuses zero, which is the "no epoch" value of a token, without writing.
[[nodiscard]] auto persist_stream_token_epoch(PersistentStore& store, std::uint64_t epoch) -> bool;
// AUTH-11: turns on retention of committed statements, bounded to `capacity`
// (clamped to `max_statement_capture_capacity`). A capacity of zero disables
// capture and drops anything held. Intended for tests that assert on the SQL and
// bound parameters a store operation produced; production never calls it.
auto enable_statement_capture(PersistentStore& store, std::size_t capacity) -> void;
// How many non-empty transactions `commit_persistent_transaction` has committed on this store. Counts commits,
// whatever the number of statements in each. Test-facing; production never reads it.
[[nodiscard]] auto committed_transaction_count(PersistentStore const& store) -> std::uint64_t;
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
    // Backend half of refresh_remote_signing_keys: `server_name`'s rows from
    // server_signing_keys, selecting server_name, key_id, public_key,
    // valid_until_ts and expired_ts only (never secret_key, so each row's secret_key is
    // empty). nullopt on a connection/query failure and for a backend with no
    // database; an unknown server is a successful empty result.
    [[nodiscard]] auto load_remote_signing_keys_from_backend(PersistentStore const& store, std::string_view server_name)
        -> std::optional<std::vector<PersistentServerSigningKey>>;
    [[nodiscard]] auto load_remote_signing_keys_from_sqlite(std::string const& path, std::string_view server_name)
        -> std::optional<std::vector<PersistentServerSigningKey>>;
    [[nodiscard]] auto load_remote_signing_keys_from_postgresql(std::string_view conninfo,
                                                                std::string_view runtime_role,
                                                                std::string_view server_name)
        -> std::optional<std::vector<PersistentServerSigningKey>>;
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
    [[nodiscard]] auto audit_rows_older_than_exist_in_sqlite(std::string const& path, std::uint64_t cutoff_ms)
        -> std::optional<bool>;
    [[nodiscard]] auto audit_rows_older_than_exist_in_postgresql(std::string_view conninfo,
                                                                 std::string_view runtime_role, std::uint64_t cutoff_ms)
        -> std::optional<bool>;
    // Test seam: called with each table's name once that table's rows of a
    // room snapshot have been read, so a test can commit between two reads.
    // Production callers pass none.
    using RoomSnapshotReadHook = std::function<void(std::string_view table)>;
    [[nodiscard]] auto load_room_snapshot_from_sqlite(std::string const& path, std::string_view room_id,
                                                      RoomSnapshotReadHook const& after_table = {})
        -> std::optional<RoomReloadSnapshot>;
    // ADR-0119: one referenced media blob's bytes. nullopt on a missing or
    // unreferenced blob and on a connection or query failure.
    [[nodiscard]] auto read_media_blob_from_sqlite(std::string const& path, std::string_view storage_id)
        -> std::optional<std::string>;
    // ADR-0574: `length` bytes of a referenced blob from `offset`. nullopt unless the blob is still referenced,
    // is exactly `expected_size` bytes long, and the whole range exists.
    [[nodiscard]] auto read_media_blob_chunk_from_sqlite(std::string const& path, std::string_view storage_id,
                                                         std::uint64_t expected_size, std::uint64_t offset,
                                                         std::size_t length) -> std::optional<std::string>;
    [[nodiscard]] auto read_media_blob_chunk_from_postgresql(std::string_view conninfo, std::string_view runtime_role,
                                                             std::string_view storage_id, std::uint64_t expected_size,
                                                             std::uint64_t offset, std::size_t length)
        -> std::optional<std::string>;
    [[nodiscard]] auto read_media_blob_from_postgresql(std::string_view conninfo, std::string_view runtime_role,
                                                       std::string_view storage_id) -> std::optional<std::string>;
    [[nodiscard]] auto load_room_snapshot_from_postgresql(std::string_view conninfo, std::string_view runtime_role,
                                                          std::string_view room_id,
                                                          RoomSnapshotReadHook const& after_table = {})
        -> std::optional<RoomReloadSnapshot>;

} // namespace detail

} // namespace merovingian::database
