// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/migration.hpp"
#include "merovingian/database/statement.hpp"
#include "merovingian/events/event.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

enum class PersistentStoreBackend
{
    memory,
    postgresql,
    sqlite,
};

struct PersistentUser final
{
    std::string user_id{};
    std::string password_hash{};
    bool locked{false};
    bool suspended{false};
    bool admin{false};
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
};

struct PersistentRefreshToken final
{
    std::string user_id{};
    std::string device_id{};
    std::string token_hash{};
    bool revoked{false};
};

struct PersistentServerSigningKey final
{
    std::string server_name{};
    std::string key_id{};
    std::string public_key{};
    std::uint64_t valid_until_ts{0U};
    std::string secret_key{}; // raw bytes; non-empty only for this server's own key
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
};

struct PersistentStateEvent final
{
    std::string room_id{};
    std::string event_type{};
    std::string state_key{};
    std::string event_id{};
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

struct PersistentStore final
{
    bool open{false};
    PersistentStoreBackend backend{PersistentStoreBackend::memory};
    std::string postgresql_conninfo{};
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
    std::vector<PersistentAuditEvent> audit_log{};
    std::vector<PersistentAdminAction> admin_actions{};
    std::vector<PersistentPolicyRule> policy_rules{};
    std::vector<PersistentAccountData> account_data{};
    std::vector<PersistentToDeviceMessage> to_device_messages{};
    std::vector<PersistentDeviceListChange> device_list_changes{};
    std::vector<PersistentPresence> presence_states{};
    std::vector<PersistentFilter> filters{};
    std::vector<PersistentProfile> profiles{};
    std::vector<PersistentRoomAlias> room_aliases{};
    std::vector<PersistentClientTxnRecord> client_txn_ids{};
    std::vector<PreparedStatement> prepared_statements{};
    // Monotonic stream id used by /sync surfaces (to_device, device_list
    // changes, presence). Incremented before each new row is persisted so
    // the row's stream_id strictly exceeds every previous one and clients
    // can compare against the since-token.
    std::uint64_t next_sync_stream_id{0U};
};

struct PersistentStoreOpenResult final
{
    bool ok{false};
    std::string reason{};
    PersistentStore store{};
};

[[nodiscard]] auto open_persistent_store(SchemaState existing_state = {}) -> PersistentStoreOpenResult;
[[nodiscard]] auto open_sqlite_persistent_store(std::string const& path) -> PersistentStoreOpenResult;
[[nodiscard]] auto validate_persistent_store(PersistentStore const& store) -> MigrationValidationResult;
[[nodiscard]] auto commit_persistent_transaction(PersistentStore& store,
                                                 std::vector<PreparedStatement> const& statements) -> bool;
[[nodiscard]] auto store_user(PersistentStore& store, PersistentUser user) -> bool;
[[nodiscard]] auto update_user_password(PersistentStore& store, std::string_view user_id, std::string_view new_hash)
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
[[nodiscard]] auto update_device_display_name(PersistentStore& store, std::string_view user_id,
                                              std::string_view device_id, std::string_view display_name) -> bool;
[[nodiscard]] auto delete_device(PersistentStore& store, std::string_view user_id, std::string_view device_id) -> bool;
[[nodiscard]] auto store_server_signing_key(PersistentStore& store, PersistentServerSigningKey key) -> bool;
[[nodiscard]] auto find_server_signing_key(PersistentStore const& store, std::string_view server_name,
                                           std::string_view key_id) -> std::optional<PersistentServerSigningKey>;
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
[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> MembershipStoreResult;
[[nodiscard]] auto update_membership(PersistentStore& store, std::string_view room_id, std::string_view user_id,
                                     std::string_view new_membership) -> bool;
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
[[nodiscard]] auto delete_all_key_backup_sessions(PersistentStore& store, std::string_view user_id) -> bool;
[[nodiscard]] auto store_local_media(PersistentStore& store, PersistentLocalMedia media) -> bool;
[[nodiscard]] auto update_local_media_state(PersistentStore& store, std::string_view media_id, bool quarantined,
                                            bool removed) -> bool;
[[nodiscard]] auto store_remote_media(PersistentStore& store, PersistentRemoteMedia media) -> bool;
[[nodiscard]] auto store_media_blob(PersistentStore& store, PersistentMediaBlob blob) -> bool;
[[nodiscard]] auto append_audit_event(PersistentStore& store, PersistentAuditEvent event) -> bool;
[[nodiscard]] auto append_admin_action(PersistentStore& store, PersistentAdminAction action) -> bool;
[[nodiscard]] auto store_policy_rule(PersistentStore& store, PersistentPolicyRule rule) -> bool;
[[nodiscard]] auto store_account_data(PersistentStore& store, PersistentAccountData data) -> bool;
[[nodiscard]] auto enqueue_to_device_message(PersistentStore& store, PersistentToDeviceMessage message) -> bool;
[[nodiscard]] auto drain_to_device_messages(PersistentStore& store, std::string_view user_id,
                                            std::string_view device_id, std::uint64_t since_stream_id)
    -> std::vector<PersistentToDeviceMessage>;
[[nodiscard]] auto record_device_list_change(PersistentStore& store, PersistentDeviceListChange change) -> bool;
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
// presence_state). Backend hydration paths call this after populating
// the in-memory mirrors so a process restart preserves the monotonic
// invariant that next_sync_stream_id is strictly greater than every
// stream id a client has ever seen.
auto restore_sync_stream_id(PersistentStore& store) -> void;
[[nodiscard]] auto sensitive_values_are_redacted(PersistentStore const& store) noexcept -> bool;

namespace detail
{

    [[nodiscard]] auto persist_statement_to_backend(PersistentStore const& store, PreparedStatement const& statement)
        -> bool;
    [[nodiscard]] auto persist_transaction_to_backend(PersistentStore const& store,
                                                      std::vector<PreparedStatement> const& statements) -> bool;
    [[nodiscard]] auto persist_transaction_to_postgresql(PersistentStore const& store,
                                                         std::vector<PreparedStatement> const& statements) -> bool;

} // namespace detail

} // namespace merovingian::database
