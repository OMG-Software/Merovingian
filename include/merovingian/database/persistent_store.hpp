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

struct PersistentServerSigningKey final
{
    std::string server_name{};
    std::string key_id{};
    std::string public_key{};
    std::uint64_t valid_until_ts{0U};
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
    std::vector<PersistentServerSigningKey> server_signing_keys{};
    std::vector<PersistentRoom> rooms{};
    std::vector<PersistentMembership> memberships{};
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
    std::vector<PersistentAuditEvent> audit_log{};
    std::vector<PersistentAdminAction> admin_actions{};
    std::vector<PreparedStatement> prepared_statements{};
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
[[nodiscard]] auto store_device(PersistentStore& store, PersistentDevice device) -> bool;
[[nodiscard]] auto store_access_token(PersistentStore& store, PersistentAccessToken token) -> bool;
[[nodiscard]] auto store_device_and_access_token(PersistentStore& store, std::optional<PersistentDevice> device,
                                                 PersistentAccessToken token) -> bool;
[[nodiscard]] auto revoke_access_token(PersistentStore& store, std::string_view token_hash) -> std::size_t;
[[nodiscard]] auto store_server_signing_key(PersistentStore& store, PersistentServerSigningKey key) -> bool;
[[nodiscard]] auto find_server_signing_key(PersistentStore const& store, std::string_view server_name,
                                           std::string_view key_id) -> std::optional<PersistentServerSigningKey>;
[[nodiscard]] auto store_room(PersistentStore& store, PersistentRoom room) -> bool;
[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> bool;
[[nodiscard]] auto store_room_with_membership(PersistentStore& store, PersistentRoom room,
                                              PersistentMembership membership) -> bool;
[[nodiscard]] auto store_event(PersistentStore& store, PersistentEvent event) -> bool;
[[nodiscard]] auto store_state(PersistentStore& store, PersistentStateEvent state) -> bool;
[[nodiscard]] auto store_event_with_state(PersistentStore& store, PersistentEvent event,
                                          std::optional<PersistentStateEvent> state) -> bool;
[[nodiscard]] auto store_device_key(PersistentStore& store, PersistentDeviceKey key) -> bool;
[[nodiscard]] auto find_device_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id)
    -> std::optional<PersistentDeviceKey>;
[[nodiscard]] auto store_one_time_key(PersistentStore& store, PersistentOneTimeKey key) -> bool;
[[nodiscard]] auto claim_one_time_key(PersistentStore& store, std::string_view user_id, std::string_view device_id)
    -> std::optional<PersistentOneTimeKey>;
[[nodiscard]] auto store_fallback_key(PersistentStore& store, PersistentFallbackKey key) -> bool;
[[nodiscard]] auto find_fallback_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id)
    -> std::optional<PersistentFallbackKey>;
[[nodiscard]] auto store_cross_signing_key(PersistentStore& store, PersistentCrossSigningKey key) -> bool;
[[nodiscard]] auto store_key_signature(PersistentStore& store, PersistentKeySignature signature) -> bool;
[[nodiscard]] auto store_key_backup_version(PersistentStore& store, PersistentKeyBackupVersion version) -> bool;
[[nodiscard]] auto store_key_backup_session(PersistentStore& store, PersistentKeyBackupSession session) -> bool;
[[nodiscard]] auto store_local_media(PersistentStore& store, PersistentLocalMedia media) -> bool;
[[nodiscard]] auto update_local_media_state(PersistentStore& store, std::string_view media_id, bool quarantined,
                                            bool removed) -> bool;
[[nodiscard]] auto store_remote_media(PersistentStore& store, PersistentRemoteMedia media) -> bool;
[[nodiscard]] auto append_audit_event(PersistentStore& store, PersistentAuditEvent event) -> bool;
[[nodiscard]] auto append_admin_action(PersistentStore& store, PersistentAdminAction action) -> bool;
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
