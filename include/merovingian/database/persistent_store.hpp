// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <merovingian/database/migration.hpp>
#include <merovingian/database/statement.hpp>

namespace merovingian::database
{

enum class PersistentStoreBackend
{
    memory,
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

struct PersistentRoom final
{
    std::string room_id{};
    std::string creator_user_id{};
};

struct PersistentMembership final
{
    std::string room_id{};
    std::string user_id{};
};

struct PersistentEvent final
{
    std::string event_id{};
    std::string room_id{};
    std::string sender_user_id{};
    std::string json{};
};

struct PersistentStateEvent final
{
    std::string room_id{};
    std::string event_type{};
    std::string state_key{};
    std::string event_id{};
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
    std::string sqlite_path{};
    SchemaState schema{};
    std::vector<PersistentUser> users{};
    std::vector<PersistentDevice> devices{};
    std::vector<PersistentAccessToken> access_tokens{};
    std::vector<PersistentRoom> rooms{};
    std::vector<PersistentMembership> memberships{};
    std::vector<PersistentEvent> events{};
    std::vector<PersistentStateEvent> state{};
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
[[nodiscard]] auto store_user(PersistentStore& store, PersistentUser user) -> bool;
[[nodiscard]] auto store_device(PersistentStore& store, PersistentDevice device) -> bool;
[[nodiscard]] auto store_access_token(PersistentStore& store, PersistentAccessToken token) -> bool;
[[nodiscard]] auto revoke_access_token(PersistentStore& store, std::string_view token_hash) -> std::size_t;
[[nodiscard]] auto store_room(PersistentStore& store, PersistentRoom room) -> bool;
[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> bool;
[[nodiscard]] auto store_event(PersistentStore& store, PersistentEvent event) -> bool;
[[nodiscard]] auto store_state(PersistentStore& store, PersistentStateEvent state) -> bool;
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

} // namespace detail

} // namespace merovingian::database
