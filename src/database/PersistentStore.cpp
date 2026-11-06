// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PersistentStore.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/crypto/constant_time.hpp"
#include "merovingian/database/DeferredPduAwaits.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/MediaBlobRead.hpp"
#include "merovingian/database/MembershipProjection.hpp"
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
#include "merovingian/database/PersistentStateTransition.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/database/PersistentThreePidBinding.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/database/PersistentUser.hpp"
#include "merovingian/database/PreparedCurrentState.hpp"
#include "merovingian/database/PreparedStateGroup.hpp"
#include "merovingian/database/PreparedStateUpdate.hpp"
#include "merovingian/database/RedactionState.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/database/UnusableCredentials.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/observability/bounded_text.hpp"
#include "merovingian/observability/logger.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <functional>
#include <iterator>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::database
{

namespace
{

    [[nodiscard]] auto current_epoch_ms() -> std::uint64_t
    {
        using namespace std::chrono;
        return static_cast<std::uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    }

} // namespace

namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("persistent_store", event, fields, severity);
    }

    [[nodiscard]] auto record_statement(std::string name, std::string sql, std::vector<BoundValue> parameters = {})
        -> PreparedStatement
    {
        return {std::move(name), std::move(sql), std::move(parameters)};
    }

    [[nodiscard]] auto record_and_persist(PersistentStore& store, PreparedStatement statement) -> bool
    {
        if (!commit_persistent_transaction(store, {statement}))
        {
            return false;
        }
        return true;
    }

    [[nodiscard]] auto token_is_hash(std::string_view token_hash) noexcept -> bool
    {
        return token_hash.starts_with("token-hash:v2:") || token_hash.starts_with("token-hash:v3:") ||
               token_hash.starts_with("token-hash:v4:");
    }

    [[nodiscard]] auto media_hash_is_valid(std::string_view hash_algorithm, std::string_view digest) noexcept -> bool
    {
        return !hash_algorithm.empty() && !digest.empty() && digest.find('/') == std::string_view::npos;
    }

    [[nodiscard]] auto top_level_json_string_field(std::string_view json, std::string_view field_name)
        -> std::optional<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& member : *object)
        {
            if (member.key == field_name)
            {
                auto const* value = std::get_if<std::string>(&member.value->storage());
                return value == nullptr ? std::nullopt : std::optional<std::string>{*value};
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] auto state_matches_event(PersistentEvent const& event, PersistentStateEvent const& state) -> bool
    {
        auto const event_type = top_level_json_string_field(event.json, "type");
        auto const state_key = top_level_json_string_field(event.json, "state_key");
        return event.event_id == state.event_id && event.room_id == state.room_id && event_type == state.event_type &&
               state_key == state.state_key;
    }

    [[nodiscard]] auto state_matches_persisted_event(PersistentStore const& store, PersistentStateEvent const& state)
        -> bool
    {
        auto const event = store.events.find(state.event_id);
        return event != store.events.end() && state_matches_event(*event, state);
    }

    [[nodiscard]] auto room_exists(PersistentStore const& store, std::string_view room_id) -> bool
    {
        return std::ranges::any_of(store.rooms, [room_id](PersistentRoom const& existing) {
            return existing.room_id == room_id;
        });
    }

    [[nodiscard]] auto room_alias_exists(PersistentStore const& store, std::string_view room_alias) -> bool
    {
        return std::ranges::any_of(store.room_aliases, [room_alias](PersistentRoomAlias const& existing) {
            return existing.room_alias == room_alias;
        });
    }

    [[nodiscard]] auto membership_exists(PersistentStore const& store, PersistentMembership const& membership) -> bool
    {
        return std::ranges::any_of(store.memberships, [&membership](PersistentMembership const& existing) {
            return existing.room_id == membership.room_id && existing.user_id == membership.user_id;
        });
    }

    [[nodiscard]] auto serialize_invite_state_events_json(std::vector<std::string> const& event_json)
        -> std::optional<std::string>
    {
        auto events = canonicaljson::Array{};
        events.reserve(event_json.size());
        for (auto const& entry_json : event_json)
        {
            auto const parsed = canonicaljson::parse_lossless(entry_json);
            if (parsed.error != canonicaljson::ParseError::none)
            {
                return std::nullopt;
            }
            events.push_back(std::move(parsed.value));
        }
        auto serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(events)});
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        return serialized.output;
    }

    [[nodiscard]] auto event_exists(PersistentStore const& store, std::string_view event_id) -> bool
    {
        return store.events.contains(event_id);
    }

    // Composite key for the in-memory state_transitions index. NUL bytes are safe
    // separators because Matrix event type/state key/room/event identifiers never
    // contain embedded NUL.
    [[nodiscard]] auto state_transition_index_key(std::string_view room_id, std::string_view event_type,
                                                  std::string_view state_key, std::string_view event_id) -> std::string
    {
        auto key = std::string{};
        key.reserve(room_id.size() + event_type.size() + state_key.size() + event_id.size() + 4U);
        key.append(room_id);
        key.push_back('\0');
        key.append(event_type);
        key.push_back('\0');
        key.append(state_key);
        key.push_back('\0');
        key.append(event_id);
        return key;
    }

    // Walk backwards through the event graph from a state event's prev_events
    // looking for the first applied state event that matches the same
    // (room_id, event_type, state_key) tuple. The immediate predecessor is also
    // checked directly against auth_events first because Matrix requires a state
    // event's auth_events to contain the previous state event for the same tuple.
    // This produces the predecessor needed for unsigned.replaces_state on
    // federated state events, which may not be the same as the local arrival-time
    // current_state for that tuple when forks exist.
    [[nodiscard]] auto find_predecessor_state_event_id(PersistentStore const& store, std::string_view room_id,
                                                       std::string_view event_type, std::string_view state_key,
                                                       std::vector<std::string> const& prev_event_ids,
                                                       std::vector<std::string> const& auth_event_ids,
                                                       std::size_t max_depth = 50U) -> std::string
    {
        for (auto const& id : auth_event_ids)
        {
            if (find_state_transition(store, room_id, event_type, state_key, id) != nullptr)
            {
                return std::string{id};
            }
        }

        auto visited = std::unordered_set<std::string>{};
        auto queue = std::deque<std::string>{};
        for (auto const& id : prev_event_ids)
        {
            if (visited.insert(id).second)
            {
                queue.push_back(id);
            }
        }

        for (auto depth = std::size_t{0U}; depth < max_depth && !queue.empty(); ++depth)
        {
            auto const level_size = queue.size();
            for (auto index = std::size_t{0U}; index < level_size; ++index)
            {
                auto id = std::move(queue.front());
                queue.pop_front();
                if (find_state_transition(store, room_id, event_type, state_key, id) != nullptr)
                {
                    return std::string{id};
                }
                auto const event = store.events.find(id);
                if (event == store.events.end())
                {
                    continue;
                }
                for (auto const& parent : event->prev_event_ids)
                {
                    if (visited.insert(parent).second)
                    {
                        queue.push_back(parent);
                    }
                }
            }
        }
        return {};
    }

    [[nodiscard]] auto device_exists(PersistentStore const& store, PersistentDevice const& device) -> bool
    {
        return std::ranges::any_of(store.devices, [&device](PersistentDevice const& existing) {
            return existing.user_id == device.user_id && existing.device_id == device.device_id;
        });
    }

    [[nodiscard]] auto access_token_exists(PersistentStore const& store, std::string_view token_hash) -> bool
    {
        return std::ranges::any_of(store.access_tokens, [token_hash](PersistentAccessToken const& existing) {
            return crypto::constant_time_equal(existing.token_hash, token_hash);
        });
    }

    [[nodiscard]] auto refresh_token_exists(PersistentStore const& store, std::string_view token_hash) -> bool
    {
        return std::ranges::any_of(store.refresh_tokens, [token_hash](PersistentRefreshToken const& existing) {
            return crypto::constant_time_equal(existing.token_hash, token_hash);
        });
    }

    [[nodiscard]] auto federation_transaction_is_valid(PersistentFederationTransaction const& transaction) noexcept
        -> bool
    {
        return !transaction.transaction_id.empty() && !transaction.server_name.empty() && !transaction.method.empty() &&
               !transaction.target.empty() && !transaction.origin.empty() && !transaction.body.empty();
    }

    [[nodiscard]] auto key_payload_is_valid(std::string_view json) noexcept -> bool
    {
        return !json.empty();
    }

    [[nodiscard]] auto sensitive_value(std::string_view value) -> BoundValue
    {
        return {std::string{value}, true};
    }

    [[nodiscard]] auto public_value(std::string_view value) -> BoundValue
    {
        return {std::string{value}, false};
    }

    auto append_event_graph_statements(std::vector<PreparedStatement>& statements, PersistentEvent const& event) -> void
    {
        for (auto const& prev_event_id : event.prev_event_ids)
        {
            statements.push_back(record_statement("insert_event_edge", "INSERT INTO event_edges VALUES ($1, $2)",
                                                  {public_value(event.event_id), public_value(prev_event_id)}));
        }
        for (auto const& auth_event_id : event.auth_event_ids)
        {
            statements.push_back(record_statement("insert_event_auth", "INSERT INTO event_auth VALUES ($1, $2)",
                                                  {public_value(event.event_id), public_value(auth_event_id)}));
        }
        for (auto const& signature : event.signatures)
        {
            statements.push_back(
                record_statement("insert_event_signature", "INSERT INTO event_signatures VALUES ($1, $2, $3, $4)",
                                 {public_value(event.event_id), public_value(signature.server_name),
                                  public_value(signature.key_id), sensitive_value(signature.signature)}));
        }
    }

    auto append_event_graph_rows(PersistentStore& store, PersistentEvent const& event) -> void
    {
        for (auto const& prev_event_id : event.prev_event_ids)
        {
            store.event_edges.push_back({event.event_id, prev_event_id});
        }
        for (auto const& auth_event_id : event.auth_event_ids)
        {
            store.event_auth.push_back({event.event_id, auth_event_id});
        }
        for (auto const& signature : event.signatures)
        {
            store.event_signatures.push_back(
                {event.event_id, signature.server_name, signature.key_id, signature.signature});
        }
    }

} // namespace

// Serialise a token expiry time_point to the TEXT column form: epoch
// milliseconds as a decimal string, or the empty string for "no expiry"
// (nullopt / legacy rows). Round-trips with parse_expires_at. Exposed so the
// SQLite/PostgreSQL store hydration can use the same encoding.
[[nodiscard]] auto expires_at_text(std::optional<std::chrono::system_clock::time_point> const& expires_at)
    -> std::string
{
    if (!expires_at.has_value())
    {
        return {};
    }
    auto const ms = std::chrono::duration_cast<std::chrono::milliseconds>(expires_at->time_since_epoch()).count();
    return std::to_string(ms);
}

// Parse the TEXT column form back into a time_point. Empty string means no
// expiry (nullopt).
//
// 0.12.5 audit, finding 24: a malformed value used to parse as nullopt — "no
// expiry" — so a corrupt or attacker-modified row turned a token that should
// have expired into a permanent credential. It now parses as the epoch, which
// every expiry comparison in the codebase reads as long past, so the token is
// rejected. Fail closed: the cost of being wrong is one re-login, and the cost
// of the previous behaviour was a credential that never expires.
[[nodiscard]] auto parse_expires_at(std::string_view text) -> std::optional<std::chrono::system_clock::time_point>
{
    if (text.empty())
    {
        return std::nullopt;
    }
    auto constexpr already_expired = std::chrono::system_clock::time_point{};
    auto buffer = std::string{text};
    char* end = nullptr;
    errno = 0;
    auto const ms = std::strtoll(buffer.c_str(), &end, 10);
    if (end == buffer.c_str() || *end != '\0' || errno != 0)
    {
        return already_expired;
    }
    return std::chrono::system_clock::time_point{std::chrono::milliseconds{ms}};
}

[[nodiscard]] auto open_persistent_store(SchemaState existing_state) -> PersistentStoreOpenResult
{
    auto plan = migration_plan_for(existing_state);
    auto applied = apply_migration_plan(std::move(existing_state), plan);
    if (!applied.ok)
    {
        return {false, applied.reason, {}};
    }
    auto store = PersistentStore{};
    store.open = true;
    store.schema = std::move(applied.state);
    auto compatibility = validate_persistent_store(store);
    if (!compatibility.valid)
    {
        return {false, compatibility.reason, {}};
    }
    return {true, {}, std::move(store)};
}

[[nodiscard]] auto validate_persistent_store(PersistentStore const& store) -> MigrationValidationResult
{
    if (!store.open)
    {
        return {false, "persistent store is not open"};
    }
    auto compatibility = schema_state_is_compatible(store.schema);
    if (!compatibility.valid)
    {
        return compatibility;
    }
    for (auto const& token : store.access_tokens)
    {
        if (!token_is_hash(token.token_hash))
        {
            return {false, "access token is not stored as a hash"};
        }
    }
    for (auto const& token : store.refresh_tokens)
    {
        if (!token_is_hash(token.token_hash))
        {
            return {false, "refresh token is not stored as a hash"};
        }
    }
    for (auto const& invite : store.invites)
    {
        if (invite.room_id.empty() || invite.user_id.empty() || invite.sender_user_id.empty() ||
            invite.event_id.empty() || invite.signed_event_json.empty())
        {
            return {false, "invite metadata is incomplete"};
        }
    }
    for (auto const& media : store.local_media)
    {
        if (!media_hash_is_valid(media.hash_algorithm, media.digest) || media.size_bytes == 0U)
        {
            return {false, "local media metadata is incomplete"};
        }
    }
    for (auto const& blob : store.media_blobs)
    {
        if (blob.storage_id.empty() || !media_hash_is_valid(blob.hash_algorithm, blob.digest) || blob.size_bytes == 0U)
        {
            return {false, "media blob metadata is incomplete"};
        }
    }
    for (auto const& rule : store.policy_rules)
    {
        if (rule.rule_id.empty() || rule.scope.empty() || rule.entity.empty() || rule.action.empty())
        {
            return {false, "policy rule metadata is incomplete"};
        }
    }
    return {true, {}};
}

auto set_write_connection_limit(PersistentStore& store, std::uint32_t limit) -> void
{
    store.write_connection_limit = std::max(limit, std::uint32_t{1U});
    if (store.sqlite_write_pool != nullptr)
    {
        detail::set_write_pool_limit(*store.sqlite_write_pool, store.write_connection_limit);
    }
    if (store.postgresql_write_pool != nullptr)
    {
        detail::set_write_pool_limit(*store.postgresql_write_pool, store.write_connection_limit);
    }
}

auto write_connections_opened(PersistentStore const& store) -> std::uint64_t
{
    return (store.sqlite_write_pool != nullptr ? detail::write_pool_opened(*store.sqlite_write_pool) : 0U) +
           (store.postgresql_write_pool != nullptr ? detail::write_pool_opened(*store.postgresql_write_pool) : 0U);
}

[[nodiscard]] auto commit_persistent_transaction(PersistentStore& store,
                                                 std::vector<PreparedStatement> const& statements) -> bool
{
    if (statements.empty())
    {
        return true;
    }
    for (auto const& statement : statements)
    {
        if (!prepared_statement_is_valid(statement).valid)
        {
            return false;
        }
    }
    if (!detail::persist_transaction_to_backend(store, statements))
    {
        return false;
    }
    {
        // AUTH-11: retain nothing unless a test opted in, and never more than the
        // configured capacity. Password hashes and token hashes must not outlive
        // the commit in process memory.
        auto const lk = std::lock_guard{*store.statement_capture_mutex};
        ++store.committed_transactions;
        if (store.statement_capture_capacity != 0U)
        {
            for (auto const& statement : statements)
            {
                store.captured_statements.push_back(statement);
                while (store.captured_statements.size() > store.statement_capture_capacity)
                {
                    store.captured_statements.pop_front();
                }
            }
        }
    }
    return true;
}

[[nodiscard]] auto store_user(PersistentStore& store, PersistentUser user) -> bool
{
    auto const duplicate = std::ranges::any_of(store.users, [&user](PersistentUser const& existing) {
        return existing.user_id == user.user_id;
    });
    if (duplicate)
    {
        return false;
    }
    // Columns are named explicitly rather than relying on a bare VALUES list:
    // positional inserts silently break the moment the table gains a column.
    if (!record_and_persist(store,
                            record_statement("insert_user",
                                             "INSERT INTO users (user_id, password_hash, locked, suspended, admin, "
                                             "deactivated) VALUES ($1, $2, $3, $4, $5, $6)",
                                             {
                                                 {user.user_id,                        false},
                                                 {user.password_hash,                  true },
                                                 {user.locked ? "true" : "false",      false},
                                                 {user.suspended ? "true" : "false",   false},
                                                 {user.admin ? "true" : "false",       false},
                                                 {user.deactivated ? "true" : "false", false}
    })))
    {
        return false;
    }
    store.users.push_back(std::move(user));
    return true;
}

[[nodiscard]] auto store_user_with_profile(PersistentStore& store, PersistentUser user, PersistentProfile profile)
    -> bool
{
    if (profile.user_id.empty() || profile.user_id != user.user_id ||
        std::ranges::any_of(store.users, [&user](PersistentUser const& existing) {
            return existing.user_id == user.user_id;
        }))
    {
        return false;
    }
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(record_statement(
        "insert_user",
        "INSERT INTO users (user_id, password_hash, locked, suspended, admin, deactivated) VALUES ($1, $2, $3, $4, "
        "$5, $6)",
        {
            {user.user_id,                        false},
            {user.password_hash,                  true },
            {user.locked ? "true" : "false",      false},
            {user.suspended ? "true" : "false",   false},
            {user.admin ? "true" : "false",       false},
            {user.deactivated ? "true" : "false", false}
    }));
    statements.push_back(record_statement(
        "upsert_profile",
        "INSERT INTO profiles (user_id, displayname, avatar_url) VALUES ($1, $2, $3) "
        "ON CONFLICT (user_id) DO UPDATE SET displayname = $2, avatar_url = $3",
        {public_value(profile.user_id), public_value(profile.displayname), public_value(profile.avatar_url)}));
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    store.users.push_back(std::move(user));
    auto const existing = std::ranges::find_if(store.profiles, [&profile](PersistentProfile const& p) {
        return p.user_id == profile.user_id;
    });
    if (existing != store.profiles.end())
    {
        *existing = std::move(profile);
    }
    else
    {
        store.profiles.push_back(std::move(profile));
    }
    return true;
}

[[nodiscard]] auto revoke_device_credentials(PersistentStore& store, std::string_view access_token_hash,
                                             std::string_view user_id, std::string_view device_id) -> bool
{
    auto statements = std::vector<PreparedStatement>{};
    statements.push_back(record_statement("revoke_access_token",
                                          "UPDATE access_tokens SET revoked = $1 WHERE token_hash = $2",
                                          {
                                              {"true",                         false},
                                              {std::string{access_token_hash}, true }
    }));
    statements.push_back(
        record_statement("revoke_device_refresh_tokens",
                         "UPDATE refresh_tokens SET revoked = $1 WHERE user_id = $2 AND "
                         "device_id = $3",
                         {
                             {"true",                 false},
                             {std::string{user_id},   false},
                             {std::string{device_id}, false}
    }));
    statements.push_back(
        record_statement("revoke_device_access_tokens",
                         "UPDATE access_tokens SET revoked = $1 WHERE user_id = $2 AND "
                         "device_id = $3",
                         {
                             {"true",                 false},
                             {std::string{user_id},   false},
                             {std::string{device_id}, false}
    }));
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    for (auto& token : store.access_tokens)
    {
        if (crypto::constant_time_equal(token.token_hash, access_token_hash) ||
            (token.user_id == user_id && token.device_id == device_id))
        {
            token.revoked = true;
        }
    }
    for (auto& token : store.refresh_tokens)
    {
        if (token.user_id == user_id && token.device_id == device_id)
        {
            token.revoked = true;
        }
    }
    return true;
}

[[nodiscard]] auto update_user_password(PersistentStore& store, std::string_view user_id, std::string_view new_hash)
    -> bool
{
    auto const it = std::ranges::find_if(store.users, [user_id](PersistentUser const& u) {
        return u.user_id == user_id;
    });
    if (it == store.users.end())
    {
        return false;
    }
    auto const statement =
        record_statement("update_user_password", "UPDATE users SET password_hash = $2 WHERE user_id = $1",
                         {public_value(user_id), sensitive_value(new_hash)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    it->password_hash = std::string{new_hash};
    return true;
}

[[nodiscard]] auto set_user_deactivated(PersistentStore& store, std::string_view user_id) -> bool
{
    auto const it = std::ranges::find_if(store.users, [user_id](PersistentUser const& u) {
        return u.user_id == user_id;
    });
    if (it == store.users.end())
    {
        return false;
    }
    auto const statement = record_statement(
        "update_user_deactivated", "UPDATE users SET deactivated = 'true' WHERE user_id = $1", {public_value(user_id)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    it->deactivated = true;
    return true;
}

[[nodiscard]] auto set_user_account_state(PersistentStore& store, std::string_view user_id, bool suspended, bool locked)
    -> bool
{
    auto const it = std::ranges::find_if(store.users, [user_id](PersistentUser const& u) {
        return u.user_id == user_id;
    });
    if (it == store.users.end())
    {
        return false;
    }
    auto const statement = record_statement(
        "update_user_account_state", "UPDATE users SET suspended = $2, locked = $3 WHERE user_id = $1",
        {public_value(user_id), public_value(suspended ? "true" : "false"), public_value(locked ? "true" : "false")});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    it->suspended = suspended;
    it->locked = locked;
    return true;
}

[[nodiscard]] auto store_device(PersistentStore& store, PersistentDevice device) -> bool
{
    if (device_exists(store, device))
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement("insert_device", "INSERT INTO devices VALUES ($1, $2, $3)",
                             {
                                 {device.user_id,      false},
                                 {device.device_id,    false},
                                 {device.display_name, false}
    })))
    {
        return false;
    }
    store.devices.push_back(std::move(device));
    return true;
}

[[nodiscard]] auto store_access_token(PersistentStore& store, PersistentAccessToken token) -> bool
{
    if (!token_is_hash(token.token_hash))
    {
        return false;
    }
    if (access_token_exists(store, token.token_hash))
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("insert_access_token",
                                                    "INSERT INTO access_tokens VALUES ($1, $2, $3, $4, $5, $6)",
                                                    {
                                                        {token.user_id,                     false},
                                                        {token.device_id,                   false},
                                                        {token.token_hash,                  true },
                                                        {token.revoked ? "true" : "false",  false},
                                                        {expires_at_text(token.expires_at), false},
                                                        {token.predecessor_refresh_hash,    true }
    })))
    {
        return false;
    }
    store.access_tokens.push_back(std::move(token));
    return true;
}

[[nodiscard]] auto store_refresh_token(PersistentStore& store, PersistentRefreshToken token) -> bool
{
    if (!token_is_hash(token.token_hash) || refresh_token_exists(store, token.token_hash))
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("insert_refresh_token",
                                                    "INSERT INTO refresh_tokens VALUES ($1, $2, $3, $4, $5, $6)",
                                                    {
                                                        {token.token_hash,                  true },
                                                        {token.user_id,                     false},
                                                        {token.device_id,                   false},
                                                        {token.revoked ? "true" : "false",  false},
                                                        {expires_at_text(token.expires_at), false},
                                                        {token.predecessor_hash,            true }
    })))
    {
        return false;
    }
    store.refresh_tokens.push_back(std::move(token));
    return true;
}

[[nodiscard]] auto store_device_and_access_token(PersistentStore& store, std::optional<PersistentDevice> device,
                                                 PersistentAccessToken token) -> bool
{
    if (!token_is_hash(token.token_hash) || access_token_exists(store, token.token_hash))
    {
        return false;
    }
    auto statements = std::vector<PreparedStatement>{};
    if (device.has_value())
    {
        if (device_exists(store, *device))
        {
            return false;
        }
        statements.push_back(
            record_statement("insert_device", "INSERT INTO devices VALUES ($1, $2, $3)",
                             {
                                 {device->user_id,      false},
                                 {device->device_id,    false},
                                 {device->display_name, false}
        }));
    }
    statements.push_back(record_statement("insert_access_token",
                                          "INSERT INTO access_tokens VALUES ($1, $2, $3, $4, $5, $6)",
                                          {
                                              {token.user_id,                     false},
                                              {token.device_id,                   false},
                                              {token.token_hash,                  true },
                                              {token.revoked ? "true" : "false",  false},
                                              {expires_at_text(token.expires_at), false},
                                              {token.predecessor_refresh_hash,    true }
    }));
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    if (device.has_value())
    {
        store.devices.push_back(std::move(*device));
    }
    store.access_tokens.push_back(std::move(token));
    return true;
}

[[nodiscard]] auto revoke_access_token(PersistentStore& store, std::string_view token_hash) -> std::size_t
{
    if (!record_and_persist(store, record_statement("revoke_access_token",
                                                    "UPDATE access_tokens SET revoked = $1 WHERE token_hash = $2",
                                                    {
                                                        {"true",                  false},
                                                        {std::string{token_hash}, true }
    })))
    {
        return 0U;
    }
    auto revoked = std::size_t{0U};
    for (auto& token : store.access_tokens)
    {
        if (crypto::constant_time_equal(token.token_hash, token_hash) && !token.revoked)
        {
            token.revoked = true;
            ++revoked;
        }
    }
    return revoked;
}

[[nodiscard]] auto revoke_refresh_token(PersistentStore& store, std::string_view token_hash) -> std::size_t
{
    if (!record_and_persist(store, record_statement("revoke_refresh_token",
                                                    "UPDATE refresh_tokens SET revoked = $1 WHERE token_hash = $2",
                                                    {
                                                        {"true",                  false},
                                                        {std::string{token_hash}, true }
    })))
    {
        return 0U;
    }
    auto revoked = std::size_t{0U};
    for (auto& token : store.refresh_tokens)
    {
        if (crypto::constant_time_equal(token.token_hash, token_hash) && !token.revoked)
        {
            token.revoked = true;
            ++revoked;
        }
    }
    return revoked;
}

[[nodiscard]] auto revoke_access_tokens_for_user(PersistentStore& store, std::string_view user_id) -> std::size_t
{
    if (!record_and_persist(store, record_statement("revoke_user_access_tokens",
                                                    "UPDATE access_tokens SET revoked = $1 WHERE user_id = $2",
                                                    {
                                                        {"true",               false},
                                                        {std::string{user_id}, false}
    })))
    {
        return 0U;
    }
    auto revoked = std::size_t{0U};
    for (auto& token : store.access_tokens)
    {
        if (token.user_id == user_id && !token.revoked)
        {
            token.revoked = true;
            ++revoked;
        }
    }
    return revoked;
}

[[nodiscard]] auto revoke_access_tokens_for_device(PersistentStore& store, std::string_view user_id,
                                                   std::string_view device_id) -> std::size_t
{
    if (!record_and_persist(
            store,
            record_statement("revoke_device_access_tokens",
                             "UPDATE access_tokens SET revoked = $1 WHERE user_id = $2 AND "
                             "device_id = $3",
                             {
                                 {"true",                 false},
                                 {std::string{user_id},   false},
                                 {std::string{device_id}, false}
    })))
    {
        return 0U;
    }
    auto revoked = std::size_t{0U};
    for (auto& token : store.access_tokens)
    {
        if (token.user_id == user_id && token.device_id == device_id && !token.revoked)
        {
            token.revoked = true;
            ++revoked;
        }
    }
    return revoked;
}

[[nodiscard]] auto revoke_refresh_tokens_for_user(PersistentStore& store, std::string_view user_id) -> std::size_t
{
    if (!record_and_persist(store, record_statement("revoke_user_refresh_tokens",
                                                    "UPDATE refresh_tokens SET revoked = $1 WHERE user_id = $2",
                                                    {
                                                        {"true",               false},
                                                        {std::string{user_id}, false}
    })))
    {
        return 0U;
    }
    auto revoked = std::size_t{0U};
    for (auto& token : store.refresh_tokens)
    {
        if (token.user_id == user_id && !token.revoked)
        {
            token.revoked = true;
            ++revoked;
        }
    }
    return revoked;
}

[[nodiscard]] auto revoke_refresh_tokens_for_device(PersistentStore& store, std::string_view user_id,
                                                    std::string_view device_id) -> std::size_t
{
    if (!record_and_persist(
            store,
            record_statement("revoke_device_refresh_tokens",
                             "UPDATE refresh_tokens SET revoked = $1 WHERE user_id = $2 AND "
                             "device_id = $3",
                             {
                                 {"true",                 false},
                                 {std::string{user_id},   false},
                                 {std::string{device_id}, false}
    })))
    {
        return 0U;
    }
    auto revoked = std::size_t{0U};
    for (auto& token : store.refresh_tokens)
    {
        if (token.user_id == user_id && token.device_id == device_id && !token.revoked)
        {
            token.revoked = true;
            ++revoked;
        }
    }
    return revoked;
}

[[nodiscard]] auto revoke_refresh_tokens_with_predecessor(PersistentStore& store, std::string_view predecessor_hash)
    -> std::size_t
{
    if (predecessor_hash.empty())
    {
        return 0U;
    }
    if (!record_and_persist(store,
                            record_statement("revoke_refresh_tokens_with_predecessor",
                                             "UPDATE refresh_tokens SET revoked = $1 WHERE predecessor_hash = $2",
                                             {
                                                 {"true",                        false},
                                                 {std::string{predecessor_hash}, true }
    })))
    {
        return 0U;
    }
    auto revoked = std::size_t{0U};
    for (auto& token : store.refresh_tokens)
    {
        if (!token.predecessor_hash.empty() && crypto::constant_time_equal(token.predecessor_hash, predecessor_hash) &&
            !token.revoked)
        {
            token.revoked = true;
            ++revoked;
        }
    }
    return revoked;
}

// M-05: revokes every access and refresh token belonging to `user_id` EXCEPT
// those of `keep_device_id`.
//
// This replaces an earlier revoke-everything-then-restore-one-device pair. That
// approach could not distinguish the tokens it had just revoked from tokens
// revoked days earlier by a logout, an admin action, or a previous password
// change, so restoring the caller's device un-revoked all of them. A password
// change is precisely the action a user takes after a compromise, and it
// resurrected the attacker's token for that device.
//
// There is deliberately no inverse "restore" helper: no code path should be
// able to un-revoke a credential. Revocation is one-way, so that a token which
// has ever been revoked can never authenticate again.
[[nodiscard]] auto revoke_tokens_for_user_except_device(PersistentStore& store, std::string_view user_id,
                                                        std::string_view keep_device_id) -> std::size_t
{
    auto revoked = std::size_t{0U};
    if (record_and_persist(
            store, record_statement(
                       "revoke_user_access_tokens_except_device",
                       "UPDATE access_tokens SET revoked = $1 WHERE user_id = $2 AND "
                       "device_id <> $3",
                       {
                           {"true",                      false},
                           {std::string{user_id},        false},
                           {std::string{keep_device_id}, false}
    })))
    {
        for (auto& token : store.access_tokens)
        {
            if (token.user_id == user_id && token.device_id != keep_device_id && !token.revoked)
            {
                token.revoked = true;
                ++revoked;
            }
        }
    }
    if (record_and_persist(
            store, record_statement(
                       "revoke_user_refresh_tokens_except_device",
                       "UPDATE refresh_tokens SET revoked = $1 WHERE user_id = $2 AND "
                       "device_id <> $3",
                       {
                           {"true",                      false},
                           {std::string{user_id},        false},
                           {std::string{keep_device_id}, false}
    })))
    {
        for (auto& token : store.refresh_tokens)
        {
            if (token.user_id == user_id && token.device_id != keep_device_id && !token.revoked)
            {
                token.revoked = true;
                ++revoked;
            }
        }
    }
    return revoked;
}

[[nodiscard]] auto update_device_display_name(PersistentStore& store, std::string_view user_id,
                                              std::string_view device_id, std::string_view display_name) -> bool
{
    auto const existing = std::ranges::find_if(store.devices, [user_id, device_id](PersistentDevice const& device) {
        return device.user_id == user_id && device.device_id == device_id;
    });
    if (existing == store.devices.end())
    {
        return false;
    }
    if (!record_and_persist(
            store, record_statement("update_device_display_name",
                                    "UPDATE devices SET display_name = $1 WHERE user_id = $2 AND "
                                    "device_id = $3",
                                    {public_value(display_name), public_value(user_id), public_value(device_id)})))
    {
        return false;
    }
    existing->display_name = std::string{display_name};
    return true;
}

[[nodiscard]] auto delete_device(PersistentStore& store, std::string_view user_id, std::string_view device_id) -> bool
{
    auto const existing = std::ranges::find_if(store.devices, [user_id, device_id](PersistentDevice const& device) {
        return device.user_id == user_id && device.device_id == device_id;
    });
    if (existing == store.devices.end())
    {
        return false;
    }
    // A deleted device's identity, one-time and fallback keys go with it, in the same transaction:
    // /keys/query returns "the current devices and identity keys", and a key left behind has
    // clients encrypting to a device that no longer exists (to-device messages for it are dropped).
    // The to-device messages addressed to this device go too, or a later login that reuses the device ID
    // receives room keys sent to the old one (ADR-0471). Broadcast rows (empty or `*` target device) belong to
    // all of the user's devices and stay.
    auto const parameters = std::vector<BoundValue>{public_value(user_id), public_value(device_id)};
    auto const statements = std::vector<PreparedStatement>{
        record_statement("delete_device", "DELETE FROM devices WHERE user_id = $1 AND device_id = $2", parameters),
        record_statement("delete_device_keys_of_device",
                         "DELETE FROM device_keys WHERE user_id = $1 AND device_id = $2", parameters),
        record_statement("delete_one_time_keys_of_device",
                         "DELETE FROM one_time_keys WHERE user_id = $1 AND device_id = $2", parameters),
        record_statement("delete_fallback_keys_of_device",
                         "DELETE FROM fallback_keys WHERE user_id = $1 AND device_id = $2", parameters),
        record_statement("delete_to_device_messages_of_device",
                         "DELETE FROM to_device_messages WHERE target_user_id = $1 AND target_device_id = $2",
                         parameters),
    };
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    store.devices.erase(existing);
    auto const of_device = [user_id, device_id](auto const& key) {
        return key.user_id == user_id && key.device_id == device_id;
    };
    std::erase_if(store.device_keys, of_device);
    std::erase_if(store.one_time_keys, of_device);
    std::erase_if(store.fallback_keys, of_device);
    std::erase_if(store.to_device_messages, [user_id, device_id](PersistentToDeviceMessage const& message) {
        return message.target_user_id == user_id && message.target_device_id == device_id;
    });
    return true;
}

[[nodiscard]] auto store_server_signing_key(PersistentStore& store, PersistentServerSigningKey key) -> bool
{
    if (key.server_name.empty() || key.key_id.empty() || key.public_key.empty() || key.valid_until_ts == 0U)
    {
        return false;
    }
    // A retired row is valid until it expired and no longer, and never holds a secret: this server's own keys
    // are retired by moving valid_until_ts, not by an expiry (ADR-0425).
    if (key.expired_ts != 0U)
    {
        if (!key.secret_key.empty())
        {
            return false;
        }
        key.valid_until_ts = key.expired_ts;
    }
    // FED-1 (ADR-0083): a row that holds a secret is a key this server
    // generated, and its public key is what our own signatures are verified
    // against. A write without a secret (a key fetched over federation, or a
    // retirement) may change its validity but never its public key, and no
    // write may give it an expiry. Checked here, before the upsert, so
    // neither the database row nor the in-memory mirror is touched; done in
    // C++ so it does not depend on how the backend stores secret_key.
    if (key.secret_key.empty())
    {
        auto const lock = std::lock_guard{*store.server_signing_keys_mutex};
        auto const existing =
            std::ranges::find_if(store.server_signing_keys, [&key](PersistentServerSigningKey const& row) {
                return row.server_name == key.server_name && row.key_id == key.key_id;
            });
        if (existing != store.server_signing_keys.end() && !existing->secret_key.empty() &&
            (existing->public_key != key.public_key || key.expired_ts != 0U))
        {
            log_diagnostic("server_signing_key.rejected",
                           {
                               {"server_name", key.server_name,                                         false},
                               {"key_id",      key.key_id,                                              false},
                               {"reason",      "secretless write would replace a generated public key", false}
            },
                           observability::LogEventSeverity::warning);
            return false;
        }
    }
    // Retirement is one way and the earliest expiry wins. The SQL applies the same rule against the stored
    // row, so two writers cannot raise an expiry between them; the in-memory merge below mirrors it.
    auto const expired_text = key.expired_ts == 0U ? std::string{} : std::to_string(key.expired_ts);
    auto const earliest_expiry =
        "CASE WHEN CAST($6 AS TEXT) = '' THEN server_signing_keys.expired_ts "
        "WHEN server_signing_keys.expired_ts = '' THEN CAST($6 AS TEXT) "
        "WHEN CAST(CAST($6 AS TEXT) AS BIGINT) < CAST(server_signing_keys.expired_ts AS BIGINT) THEN CAST($6 AS TEXT) "
        "ELSE server_signing_keys.expired_ts END";
    auto const upsert =
        std::string{"INSERT INTO server_signing_keys VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (server_name, key_id) "
                    "DO UPDATE SET public_key = CASE WHEN server_signing_keys.expired_ts = '' THEN $3 "
                    "ELSE server_signing_keys.public_key END, valid_until_ts = CASE WHEN CAST($6 AS TEXT) = '' AND "
                    "server_signing_keys.expired_ts = '' THEN $4 WHEN CAST($6 AS TEXT) = '' THEN "
                    "server_signing_keys.expired_ts WHEN server_signing_keys.expired_ts = '' THEN CAST($6 AS TEXT) "
                    "WHEN CAST(CAST($6 AS TEXT) AS BIGINT) < CAST(server_signing_keys.expired_ts AS BIGINT) THEN "
                    "CAST($6 AS TEXT) ELSE server_signing_keys.expired_ts END, expired_ts = "} +
        earliest_expiry + ", secret_key = CASE WHEN $5 = '' THEN server_signing_keys.secret_key ELSE $5 END";
    if (!record_and_persist(store, record_statement("upsert_server_signing_key", upsert,
                                                    {
                                                        public_value(key.server_name),
                                                        public_value(key.key_id),
                                                        public_value(key.public_key),
                                                        public_value(std::to_string(key.valid_until_ts)),
                                                        // `secret_key` is a BLOB column: bind it as binary so it is
                                                        // byte-exact on PostgreSQL (still sensitive: never traced).
                                                        {key.secret_key, true, true},
                                                        public_value(expired_text),
    })))
    {
        return false;
    }
    auto const lock = std::lock_guard{*store.server_signing_keys_mutex};
    auto const existing =
        std::ranges::find_if(store.server_signing_keys, [&key](PersistentServerSigningKey const& row) {
            return row.server_name == key.server_name && row.key_id == key.key_id;
        });
    if (existing != store.server_signing_keys.end())
    {
        if (existing->expired_ts == 0U)
        {
            existing->public_key = std::move(key.public_key);
        }
        if (key.expired_ts != 0U)
        {
            existing->expired_ts =
                existing->expired_ts == 0U ? key.expired_ts : std::min(existing->expired_ts, key.expired_ts);
        }
        existing->valid_until_ts = existing->expired_ts != 0U ? existing->expired_ts : key.valid_until_ts;
        if (!key.secret_key.empty())
        {
            existing->secret_key = std::move(key.secret_key);
        }
        return true;
    }
    store.server_signing_keys.push_back(std::move(key));
    return true;
}

[[nodiscard]] auto find_server_signing_key(PersistentStore const& store, std::string_view server_name,
                                           std::string_view key_id) -> std::optional<PersistentServerSigningKey>
{
    auto const lock = std::lock_guard{*store.server_signing_keys_mutex};
    auto const existing =
        std::ranges::find_if(store.server_signing_keys, [server_name, key_id](PersistentServerSigningKey const& key) {
            return key.server_name == server_name && key.key_id == key_id;
        });
    return existing == store.server_signing_keys.end() ? std::nullopt
                                                       : std::optional<PersistentServerSigningKey>{*existing};
}

[[nodiscard]] auto snapshot_server_signing_keys(PersistentStore const& store) -> std::vector<PersistentServerSigningKey>
{
    auto const lock = std::lock_guard{*store.server_signing_keys_mutex};
    return store.server_signing_keys;
}

[[nodiscard]] auto refresh_remote_signing_keys(PersistentStore& store, std::string_view server_name) -> bool
{
    if (store.backend == PersistentStoreBackend::memory)
    {
        return true;
    }
    auto rows = detail::load_remote_signing_keys_from_backend(store, server_name);
    if (!rows.has_value())
    {
        log_diagnostic("server_signing_keys.refresh_failed",
                       {
                           {"server_name", std::string{server_name}, false}
        },
                       observability::LogEventSeverity::warning);
        return false;
    }
    auto const lock = std::lock_guard{*store.server_signing_keys_mutex};
    for (auto& row : *rows)
    {
        // Only the public columns were read. A row this process holds with a
        // secret is this server's own key: leave it exactly as it is.
        auto const existing =
            std::ranges::find_if(store.server_signing_keys, [&row](PersistentServerSigningKey const& held) {
                return held.server_name == row.server_name && held.key_id == row.key_id;
            });
        if (existing == store.server_signing_keys.end())
        {
            store.server_signing_keys.push_back(std::move(row));
        }
        else if (existing->secret_key.empty())
        {
            // The database is authoritative, but retirement is one way here too: a retired row stays retired
            // and keeps its key and the earlier expiry.
            if (existing->expired_ts == 0U)
            {
                existing->public_key = std::move(row.public_key);
            }
            if (row.expired_ts != 0U)
            {
                existing->expired_ts =
                    existing->expired_ts == 0U ? row.expired_ts : std::min(existing->expired_ts, row.expired_ts);
            }
            existing->valid_until_ts = existing->expired_ts != 0U ? existing->expired_ts : row.valid_until_ts;
        }
    }
    return true;
}

[[nodiscard]] auto store_federation_destination(PersistentStore& store, PersistentFederationDestination destination)
    -> bool
{
    if (destination.server_name.empty() || destination.state.empty())
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement("upsert_federation_destination",
                             "INSERT INTO federation_destinations VALUES ($1, $2, $3, $4, $5) ON CONFLICT "
                             "(server_name) DO UPDATE SET state = $2, retry_after_ts = $3, last_success_ts = $4, "
                             "consecutive_failures = $5",
                             {public_value(destination.server_name), public_value(destination.state),
                              public_value(std::to_string(destination.retry_after_ts)),
                              public_value(std::to_string(destination.last_success_ts)),
                              public_value(std::to_string(destination.consecutive_failures))})))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.federation_destinations,
                                               [&destination](PersistentFederationDestination const& current) {
                                                   return current.server_name == destination.server_name;
                                               });
    if (existing != store.federation_destinations.end())
    {
        *existing = std::move(destination);
        return true;
    }
    store.federation_destinations.push_back(std::move(destination));
    return true;
}

namespace
{

    [[nodiscard]] auto upsert_federation_transaction_statement(PersistentFederationTransaction const& transaction)
        -> PreparedStatement
    {
        return record_statement(
            "upsert_federation_transaction",
            "INSERT INTO federation_transactions (transaction_id, server_name, json, method, target, origin, "
            "origin_server_ts, body, retry_count, next_retry_ts) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, "
            "$10) ON CONFLICT (transaction_id) DO UPDATE SET server_name = $2, json = $3, method = $4, target = "
            "$5, origin = $6, origin_server_ts = $7, body = $8, retry_count = $9, next_retry_ts = $10",
            {public_value(transaction.transaction_id), public_value(transaction.server_name),
             sensitive_value(transaction.body), public_value(transaction.method), public_value(transaction.target),
             public_value(transaction.origin), public_value(transaction.origin_server_ts),
             sensitive_value(transaction.body), public_value(std::to_string(transaction.retry_count)),
             public_value(std::to_string(transaction.next_retry_ts))});
    }

    [[nodiscard]] auto federation_transaction_index_in_step(PersistentStore const& store) noexcept -> bool
    {
        return store.federation_transaction_indexed_rows == store.federation_transactions.size();
    }

    // The position of the transaction `transaction_id` names. Through the index while it is in step, else by scan.
    [[nodiscard]] auto find_federation_transaction_position(PersistentStore const& store,
                                                            std::string_view transaction_id)
        -> std::optional<std::size_t>
    {
        if (federation_transaction_index_in_step(store))
        {
            auto const entry = store.federation_transaction_index.find(std::string{transaction_id});
            if (entry == store.federation_transaction_index.end())
            {
                return std::nullopt;
            }
            if (entry->second < store.federation_transactions.size() &&
                store.federation_transactions[entry->second].transaction_id == transaction_id)
            {
                return entry->second;
            }
        }
        for (auto position = std::size_t{0U}; position < store.federation_transactions.size(); ++position)
        {
            if (store.federation_transactions[position].transaction_id == transaction_id)
            {
                return position;
            }
        }
        return std::nullopt;
    }

} // namespace

auto rebuild_federation_transaction_index(PersistentStore& store) -> void
{
    store.federation_transaction_index.clear();
    store.federation_transaction_index.reserve(store.federation_transactions.size());
    for (auto position = std::size_t{0U}; position < store.federation_transactions.size(); ++position)
    {
        store.federation_transaction_index.emplace(store.federation_transactions[position].transaction_id, position);
    }
    store.federation_transaction_indexed_rows = store.federation_transactions.size();
}

[[nodiscard]] auto store_federation_transactions(PersistentStore& store,
                                                 std::vector<PersistentFederationTransaction> transactions) -> bool
{
    if (transactions.empty())
    {
        return true;
    }
    if (!std::ranges::all_of(transactions, [](PersistentFederationTransaction const& transaction) {
            return federation_transaction_is_valid(transaction);
        }))
    {
        return false;
    }
    auto statements = std::vector<PreparedStatement>{};
    statements.reserve(transactions.size());
    for (auto const& transaction : transactions)
    {
        statements.push_back(upsert_federation_transaction_statement(transaction));
    }
    // One commit for the whole batch (ADR-0441): every row is durable together or none is, and the mirror
    // below changes only after the commit, so a failure leaves memory and the database equal.
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    if (!federation_transaction_index_in_step(store))
    {
        rebuild_federation_transaction_index(store);
    }
    for (auto& transaction : transactions)
    {
        if (auto const position = find_federation_transaction_position(store, transaction.transaction_id);
            position.has_value())
        {
            store.federation_transactions[*position] = std::move(transaction);
            continue;
        }
        store.federation_transaction_index.emplace(transaction.transaction_id, store.federation_transactions.size());
        store.federation_transactions.push_back(std::move(transaction));
        store.federation_transaction_indexed_rows = store.federation_transactions.size();
    }
    return true;
}

[[nodiscard]] auto store_federation_transaction(PersistentStore& store, PersistentFederationTransaction transaction)
    -> bool
{
    auto batch = std::vector<PersistentFederationTransaction>{};
    batch.push_back(std::move(transaction));
    return store_federation_transactions(store, std::move(batch));
}

[[nodiscard]] auto delete_federation_transaction(PersistentStore& store, std::string_view transaction_id) -> bool
{
    if (transaction_id.empty())
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("delete_federation_transaction",
                                                    "DELETE FROM federation_transactions WHERE transaction_id = $1",
                                                    {public_value(transaction_id)})))
    {
        return false;
    }
    auto const position = find_federation_transaction_position(store, transaction_id);
    if (!position.has_value())
    {
        return true;
    }
    store.federation_transactions.erase(store.federation_transactions.begin() + static_cast<std::ptrdiff_t>(*position));
    rebuild_federation_transaction_index(store);
    return true;
}

auto reconstruct_event_relations(PersistentStore& store) -> void
{
    // Gathered by row position first, then written with one modify() per row.
    auto const count = store.events.size();
    auto prev_event_ids = std::vector<std::vector<std::string>>(count);
    auto auth_event_ids = std::vector<std::vector<std::string>>(count);
    auto signatures = std::vector<std::vector<events::EventSignature>>(count);
    auto const position_of = [&store](std::string_view event_id) -> std::optional<std::size_t> {
        auto const event = store.events.find(event_id);
        if (event == store.events.end())
        {
            return std::nullopt;
        }
        return static_cast<std::size_t>(event - store.events.begin());
    };
    for (auto const& edge : store.event_edges)
    {
        if (auto const position = position_of(edge.event_id))
        {
            prev_event_ids[*position].push_back(edge.prev_event_id);
        }
    }
    for (auto const& auth : store.event_auth)
    {
        if (auto const position = position_of(auth.event_id))
        {
            auth_event_ids[*position].push_back(auth.auth_event_id);
        }
    }
    for (auto const& signature : store.event_signatures)
    {
        if (auto const position = position_of(signature.event_id))
        {
            signatures[*position].push_back({signature.server_name, signature.key_id, signature.signature});
        }
    }
    for (auto position = std::size_t{0U}; position < count; ++position)
    {
        store.events.modify(store.events.begin() + static_cast<std::ptrdiff_t>(position), [&](PersistentEvent& event) {
            event.prev_event_ids = std::move(prev_event_ids[position]);
            event.auth_event_ids = std::move(auth_event_ids[position]);
            event.signatures = std::move(signatures[position]);
        });
    }
}

[[nodiscard]] auto load_room_snapshot(PersistentStore const& store, std::string_view room_id)
    -> std::optional<RoomReloadSnapshot>
{
    if (store.backend == PersistentStoreBackend::memory)
    {
        auto unchanged = RoomReloadSnapshot{};
        unchanged.nothing_to_apply = true;
        return unchanged;
    }
    auto snapshot = detail::load_room_snapshot_from_backend(store, room_id);
    if (!snapshot.has_value())
    {
        log_diagnostic("room.reload_failed",
                       {
                           {"room_id", std::string{room_id}, false}
        },
                       observability::LogEventSeverity::warning);
    }
    else
    {
        snapshot->room_id = std::string{room_id};
    }
    return snapshot;
}

[[nodiscard]] auto reload_room(PersistentStore& store, std::string_view room_id) -> bool
{
    auto snapshot = load_room_snapshot(store, room_id);
    if (!snapshot.has_value())
    {
        return false;
    }
    apply_room_snapshot(store, std::move(*snapshot));
    return true;
}

auto apply_room_snapshot(PersistentStore& store, RoomReloadSnapshot snapshot) -> void
{
    if (snapshot.nothing_to_apply)
    {
        return;
    }
    auto const& room_id = snapshot.room_id;

    // Replace this room's slice of the store: drop every existing row keyed
    // to room_id (rooms/memberships/invites/state and this room's own
    // events), plus the relation-table rows keyed to those event ids, then
    // insert the freshly-read snapshot. Erasing by event id (not just
    // room_id) before reinserting is what keeps event_edges/event_auth/
    // event_signatures from accumulating duplicates across repeated reloads.
    auto stale_event_ids = std::unordered_set<std::string>{};
    for (auto const& event : store.events.room_in_stream_order(room_id))
    {
        stale_event_ids.insert(event.event_id);
    }
    for (auto const& event : snapshot.events)
    {
        stale_event_ids.insert(event.event_id);
    }

    std::erase_if(store.rooms, [&](PersistentRoom const& r) {
        return r.room_id == room_id;
    });
    std::erase_if(store.memberships, [&](PersistentMembership const& m) {
        return m.room_id == room_id;
    });
    std::erase_if(store.invites, [&](PersistentInvite const& i) {
        return i.room_id == room_id;
    });
    std::erase_if(store.state, [&](PersistentStateEvent const& s) {
        return s.room_id == room_id;
    });
    std::ignore = store.events.erase_if([&](PersistentEvent const& e) {
        return e.room_id == room_id;
    });
    std::erase_if(store.event_edges, [&](PersistentEventEdge const& e) {
        return stale_event_ids.contains(e.event_id);
    });
    std::erase_if(store.event_auth, [&](PersistentEventAuth const& e) {
        return stale_event_ids.contains(e.event_id);
    });
    std::erase_if(store.event_signatures, [&](PersistentEventSignature const& e) {
        return stale_event_ids.contains(e.event_id);
    });

    // The room's state groups (ADR-0064): the groups keyed to room_id, the entries of those groups,
    // and the room's events' group mappings. Federation reads judge an event on its recorded group
    // and fail closed without one, so a worker that reloaded the events but not the groups would
    // treat every event created after it started as invisible. Only this room's rows are touched.
    auto stale_group_ids = std::unordered_set<std::string>{};
    for (auto const& group : store.state_groups)
    {
        if (group.room_id == room_id)
        {
            stale_group_ids.insert(group.state_group_id);
        }
    }
    for (auto const& group : snapshot.state_groups)
    {
        stale_group_ids.insert(group.state_group_id);
    }
    std::ignore = store.state_groups.erase_if([&](PersistentStateGroup const& g) {
        return stale_group_ids.contains(g.state_group_id);
    });
    std::ignore = store.state_group_state.erase_if([&](PersistentStateGroupStateEntry const& e) {
        return stale_group_ids.contains(e.state_group_id);
    });
    std::ignore = store.event_state_groups.erase_if([&](PersistentEventStateGroup const& m) {
        return stale_event_ids.contains(m.event_id);
    });
    std::ignore = store.state_groups.insert_all(std::move(snapshot.state_groups));
    store.state_group_state.insert_all(std::move(snapshot.state_group_state));
    store.event_state_groups.insert_all(std::move(snapshot.event_state_groups));

    if (snapshot.room.has_value())
    {
        store.rooms.push_back(std::move(*snapshot.room));
    }
    for (auto& membership : snapshot.memberships)
    {
        store.memberships.push_back(std::move(membership));
    }
    for (auto& invite : snapshot.invites)
    {
        store.invites.push_back(std::move(invite));
    }
    for (auto& state : snapshot.state)
    {
        store.state.push_back(std::move(state));
    }
    // The erase above shifted every later row; a pushed row alone would not repair the indexes.
    rebuild_state_index(store);
    rebuild_membership_index(store);
    for (auto& event : snapshot.events)
    {
        for (auto const& prev_id : event.prev_event_ids)
        {
            store.event_edges.push_back({event.event_id, prev_id});
        }
        for (auto const& auth_id : event.auth_event_ids)
        {
            store.event_auth.push_back({event.event_id, auth_id});
        }
        for (auto const& signature : event.signatures)
        {
            store.event_signatures.push_back(
                {event.event_id, signature.server_name, signature.key_id, signature.signature});
        }
    }
    std::ignore = store.events.insert_all(std::move(snapshot.events));
}

namespace
{

    // ADR-0315: the largest value a BIGINT row holds.
    constexpr auto max_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

} // namespace

// Requests take sync positions after they store an event or a membership, some of them inside helpers
// that throw at the ceiling. Refusing the write while positions remain means those requests never reach
// the throw with the write already committed.
[[nodiscard]] auto sync_stream_has_write_reserve(PersistentStore const& store) -> bool
{
    if (store.next_sync_stream_id < max_sync_stream_id - sync_stream_write_reserve)
    {
        return true;
    }
    log_diagnostic("sync_stream.write_refused", {
                                                    {"reason", "counter is near its ceiling", false}
    });
    return false;
}

[[nodiscard]] auto store_room(PersistentStore& store, PersistentRoom room) -> bool
{
    if (!sync_stream_has_write_reserve(store) || room_exists(store, room.room_id))
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement("insert_room",
                             "INSERT INTO rooms (room_id, creator_user_id, directory_public) VALUES ($1, $2, $3)",
                             {
                                 {room.room_id,                             false},
                                 {room.creator_user_id,                     false},
                                 {room.directory_public ? "true" : "false", false}
    })))
    {
        return false;
    }
    store.rooms.push_back(std::move(room));
    return true;
}

[[nodiscard]] auto set_room_directory_public(PersistentStore& store, std::string_view room_id, bool directory_public)
    -> bool
{
    auto const room = std::ranges::find_if(store.rooms, [room_id](PersistentRoom const& candidate) {
        return candidate.room_id == room_id;
    });
    if (room == store.rooms.end())
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement("set_room_directory_public", "UPDATE rooms SET directory_public = $2 WHERE room_id = $1",
                             {public_value(std::string{room_id}), public_value(directory_public ? "true" : "false")})))
    {
        return false;
    }
    room->directory_public = directory_public;
    return true;
}

namespace
{

    // DB-4: a join, leave or ban ends any pending invite; an invite records one, and
    // so does a knock on a room on another server (its knock_room_state, ADR-0243).
    [[nodiscard]] auto membership_ends_invite(std::string_view membership) noexcept -> bool
    {
        return membership == "join" || membership == "leave" || membership == "ban";
    }

    [[nodiscard]] auto membership_records_invite(std::string_view membership) noexcept -> bool
    {
        return membership == "invite" || membership == "knock";
    }

    [[nodiscard]] auto membership_projection_is_valid(MembershipProjection const& projection) noexcept -> bool
    {
        return !projection.user_id.empty() && !projection.membership.empty() &&
               (!projection.invite.has_value() || membership_records_invite(projection.membership));
    }

    // The statements that write `projection` for `room_id`. Upserts, so the
    // statements do not depend on what the in-memory mirror held when they were
    // built: prepare_store_event_with_state may commit with the lock released.
    [[nodiscard]] auto append_membership_projection_statements(std::vector<PreparedStatement>& statements,
                                                               std::string_view room_id,
                                                               MembershipProjection const& projection) -> bool
    {
        statements.push_back(record_statement(
            "upsert_membership",
            "INSERT INTO membership (room_id, user_id, membership, stream_ordering) VALUES ($1, $2, "
            "$3, $4) ON CONFLICT (room_id, user_id) DO UPDATE SET membership = $3, stream_ordering = $4",
            {public_value(room_id), public_value(projection.user_id), public_value(projection.membership),
             public_value(std::to_string(projection.stream_ordering))}));
        if (membership_records_invite(projection.membership) && projection.invite.has_value())
        {
            auto const& invite = *projection.invite;
            auto const invite_state_json = serialize_invite_state_events_json(invite.invite_state_events_json);
            if (!invite_state_json.has_value())
            {
                return false;
            }
            statements.push_back(record_statement(
                "upsert_invite",
                "INSERT INTO invites (room_id, user_id, sender_user_id, event_id, signed_event_json, "
                "invite_state_json, stream_ordering, resident_server) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "
                "ON CONFLICT (room_id, user_id) DO UPDATE SET sender_user_id = $3, event_id = $4, "
                "signed_event_json = $5, invite_state_json = $6, stream_ordering = $7, resident_server = $8",
                {public_value(room_id), public_value(projection.user_id), public_value(invite.sender_user_id),
                 public_value(invite.event_id), sensitive_value(invite.signed_event_json),
                 sensitive_value(*invite_state_json), public_value(std::to_string(invite.stream_ordering)),
                 public_value(invite.resident_server)}));
        }
        else if (membership_ends_invite(projection.membership))
        {
            statements.push_back(record_statement("delete_invite",
                                                  "DELETE FROM invites WHERE room_id = $1 AND user_id = $2",
                                                  {public_value(room_id), public_value(projection.user_id)}));
        }
        return true;
    }

    // Adds the row just appended to `memberships` to the per-room index, if the index was in step before it. If it
    // was not (something edited the vector behind the store's back) it stays out of step, so readers scan, until
    // the next rebuild.
    auto note_membership_row_appended(PersistentStore& store) -> void
    {
        if (store.memberships.empty() || store.membership_indexed_rows + 1U != store.memberships.size())
        {
            return;
        }
        auto const position = store.memberships.size() - 1U;
        store.membership_room_index[store.memberships[position].room_id].push_back(position);
        store.membership_indexed_rows = store.memberships.size();
    }

    // Mirrors committed projection statements into the in-memory rows.
    auto apply_membership_projection(PersistentStore& store, std::string_view room_id,
                                     MembershipProjection const& projection) -> void
    {
        auto const row = std::ranges::find_if(store.memberships, [&](PersistentMembership const& membership) {
            return membership.room_id == room_id && membership.user_id == projection.user_id;
        });
        if (row == store.memberships.end())
        {
            store.memberships.push_back(
                {std::string{room_id}, projection.user_id, projection.membership, projection.stream_ordering});
            note_membership_row_appended(store);
        }
        else
        {
            row->membership = projection.membership;
            row->stream_ordering = projection.stream_ordering;
        }

        auto const invite = std::ranges::find_if(store.invites, [&](PersistentInvite const& current) {
            return current.room_id == room_id && current.user_id == projection.user_id;
        });
        if (membership_records_invite(projection.membership) && projection.invite.has_value())
        {
            auto written = *projection.invite;
            written.room_id = std::string{room_id};
            written.user_id = projection.user_id;
            if (invite == store.invites.end())
            {
                store.invites.push_back(std::move(written));
            }
            else
            {
                *invite = std::move(written);
            }
        }
        else if (membership_ends_invite(projection.membership) && invite != store.invites.end())
        {
            store.invites.erase(invite);
        }
        log_diagnostic("membership.projected",
                       {
                           {"room_id",         std::string{room_id},                       false},
                           {"user_id",         projection.user_id,                         false},
                           {"membership",      projection.membership,                      false},
                           {"stream_ordering", std::to_string(projection.stream_ordering), false}
        });
    }

    // content.membership of an m.room.member event's JSON, or nullopt.
    [[nodiscard]] auto content_membership_of(std::string_view event_json) -> std::optional<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (event == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& member : *event)
        {
            if (member.key != "content")
            {
                continue;
            }
            auto const* content = std::get_if<canonicaljson::Object>(&member.value->storage());
            if (content == nullptr)
            {
                return std::nullopt;
            }
            for (auto const& field : *content)
            {
                if (field.key == "membership")
                {
                    auto const* value = std::get_if<std::string>(&field.value->storage());
                    return value == nullptr || value->empty() ? std::nullopt : std::optional<std::string>{*value};
                }
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

} // namespace

[[nodiscard]] auto store_membership_projection(PersistentStore& store, std::string_view room_id,
                                               MembershipProjection projection) -> bool
{
    auto statements = std::vector<PreparedStatement>{};
    if (!sync_stream_has_write_reserve(store) || room_id.empty() || !membership_projection_is_valid(projection) ||
        !append_membership_projection_statements(statements, room_id, projection) ||
        !commit_persistent_transaction(store, statements))
    {
        log_diagnostic("membership.projection.rejected", {
                                                             {"room_id",    std::string{room_id},  false},
                                                             {"user_id",    projection.user_id,    false},
                                                             {"membership", projection.membership, false}
        });
        return false;
    }
    apply_membership_projection(store, room_id, projection);
    return true;
}

[[nodiscard]] auto reconcile_memberships_with_current_state(
    PersistentStore& store, std::function<std::uint64_t()> const& allocate_stream_ordering) -> std::size_t
{
    // The current m.room.member event of every (room, user), found in one pass.
    auto member_events = std::unordered_map<std::string, PersistentEvent const*>{};
    for (auto const& state : store.state)
    {
        if (state.event_type == "m.room.member")
        {
            member_events.emplace(state.event_id, nullptr);
        }
    }
    for (auto const& event : store.events)
    {
        if (auto const found = member_events.find(event.event_id); found != member_events.end())
        {
            found->second = &event;
        }
    }

    // Every row by (room, user), so a large server reconciles in O(n log n).
    auto rows = std::map<std::pair<std::string_view, std::string_view>, PersistentMembership const*>{};
    for (auto const& membership : store.memberships)
    {
        rows.emplace(std::pair<std::string_view, std::string_view>{membership.room_id, membership.user_id},
                     &membership);
    }

    struct Correction final
    {
        std::string room_id{};
        MembershipProjection projection{};
    };
    auto corrections = std::vector<Correction>{};
    for (auto const& state : store.state)
    {
        if (state.event_type != "m.room.member")
        {
            continue;
        }
        auto const found = member_events.find(state.event_id);
        if (found == member_events.end() || found->second == nullptr || found->second->room_id != state.room_id)
        {
            continue;
        }
        auto const& event = *found->second;
        auto membership = content_membership_of(event.json);
        if (!membership.has_value())
        {
            continue;
        }
        auto const indexed = rows.find({state.room_id, state.state_key});
        auto const* row = indexed == rows.end() ? nullptr : indexed->second;
        auto const stale =
            row == nullptr || (row->membership != *membership &&
                               (row->membership == "join" || event.stream_ordering > row->stream_ordering));
        if (stale)
        {
            corrections.push_back({
                state.room_id, {state.state_key, std::move(*membership), 0U, std::nullopt}
            });
        }
    }
    if (corrections.empty())
    {
        return 0U;
    }

    auto statements = std::vector<PreparedStatement>{};
    for (auto& correction : corrections)
    {
        correction.projection.stream_ordering = allocate_stream_ordering();
        std::ignore = append_membership_projection_statements(statements, correction.room_id, correction.projection);
    }
    // In memory regardless: the rows then say what current_state, already
    // durable, says. A failed write is retried at the next startup.
    auto const persisted = commit_persistent_transaction(store, statements);
    for (auto const& correction : corrections)
    {
        apply_membership_projection(store, correction.room_id, correction.projection);
    }
    log_diagnostic("membership.reconciled",
                   {
                       {"corrected", std::to_string(corrections.size()), false},
                       {"persisted", persisted ? "true" : "false",       false}
    },
                   observability::LogEventSeverity::warning);
    return corrections.size();
}

[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> MembershipStoreResult
{
    if (!sync_stream_has_write_reserve(store))
    {
        return MembershipStoreResult::error;
    }
    if (membership_exists(store, membership))
    {
        log_diagnostic("membership.rejected", {
                                                  {"room_id",    membership.room_id,     false},
                                                  {"user_id",    membership.user_id,     false},
                                                  {"membership", membership.membership,  false},
                                                  {"reason",     "duplicate membership", false}
        });
        return MembershipStoreResult::already_exists;
    }
    if (!record_and_persist(store,
                            record_statement("insert_membership", "INSERT INTO membership VALUES ($1, $2, $3, $4)",
                                             {
                                                 {membership.room_id,                         false},
                                                 {membership.user_id,                         false},
                                                 {membership.membership,                      false},
                                                 {std::to_string(membership.stream_ordering), false}
    })))
    {
        log_diagnostic("membership.rejected", {
                                                  {"room_id",    membership.room_id,                    false},
                                                  {"user_id",    membership.user_id,                    false},
                                                  {"membership", membership.membership,                 false},
                                                  {"reason",     "persistence backend rejected insert", false}
        });
        return MembershipStoreResult::error;
    }
    log_diagnostic("membership.persisted", {
                                               {"room_id",         membership.room_id,                         false},
                                               {"user_id",         membership.user_id,                         false},
                                               {"membership",      membership.membership,                      false},
                                               {"stream_ordering", std::to_string(membership.stream_ordering), false}
    });
    store.memberships.push_back(std::move(membership));
    note_membership_row_appended(store);
    return MembershipStoreResult::stored;
}

[[nodiscard]] auto update_membership(PersistentStore& store, std::string_view room_id, std::string_view user_id,
                                     std::string_view new_membership, std::uint64_t stream_ordering) -> bool
{
    if (!sync_stream_has_write_reserve(store))
    {
        return false;
    }
    auto const it = std::ranges::find_if(store.memberships, [&](PersistentMembership const& m) {
        return m.room_id == room_id && m.user_id == user_id;
    });
    if (it == store.memberships.end())
    {
        log_diagnostic("membership.update.rejected", {
                                                         {"room_id", std::string{room_id},   false},
                                                         {"user_id", std::string{user_id},   false},
                                                         {"reason",  "membership not found", false}
        });
        return false;
    }
    // stream_ordering MUST advance on every transition, not just on first
    // insert: /sync's since-token comparisons (rooms.leave inclusion,
    // joined_membership_changed_since) key off this column to detect "did
    // this membership change recently" — leaving it frozen at the row's
    // original insert value means a later transition (join -> leave, a kick,
    // a re-invite, ...) is silently invisible to any client polling
    // incrementally, even though the row's `membership` value is correct.
    if (!record_and_persist(
            store,
            record_statement("update_membership",
                             "UPDATE membership SET membership = $3, stream_ordering = $4 WHERE room_id = $1 AND "
                             "user_id = $2",
                             {
                                 {std::string{room_id},            false},
                                 {std::string{user_id},            false},
                                 {std::string{new_membership},     false},
                                 {std::to_string(stream_ordering), false}
    })))
    {
        log_diagnostic("membership.update.rejected", {
                                                         {"room_id", std::string{room_id},                  false},
                                                         {"user_id", std::string{user_id},                  false},
                                                         {"reason",  "persistence backend rejected update", false}
        });
        return false;
    }
    it->membership = std::string{new_membership};
    it->stream_ordering = stream_ordering;
    log_diagnostic("membership.updated", {
                                             {"room_id",         std::string{room_id},            false},
                                             {"user_id",         std::string{user_id},            false},
                                             {"membership",      std::string{new_membership},     false},
                                             {"stream_ordering", std::to_string(stream_ordering), false}
    });
    return true;
}

[[nodiscard]] auto delete_membership(PersistentStore& store, std::string_view room_id, std::string_view user_id) -> bool
{
    auto const it = std::ranges::find_if(store.memberships, [&](PersistentMembership const& membership) {
        return membership.room_id == room_id && membership.user_id == user_id;
    });
    if (it == store.memberships.end())
    {
        log_diagnostic("membership.delete.rejected", {
                                                         {"room_id", std::string{room_id},   false},
                                                         {"user_id", std::string{user_id},   false},
                                                         {"reason",  "membership not found", false}
        });
        return false;
    }
    if (!record_and_persist(
            store, record_statement("delete_membership", "DELETE FROM membership WHERE room_id = $1 AND user_id = $2",
                                    {public_value(std::string{room_id}), public_value(std::string{user_id})})))
    {
        log_diagnostic("membership.delete.rejected", {
                                                         {"room_id", std::string{room_id},                  false},
                                                         {"user_id", std::string{user_id},                  false},
                                                         {"reason",  "persistence backend rejected delete", false}
        });
        return false;
    }
    store.memberships.erase(it);
    // The erase shifted every later row.
    rebuild_membership_index(store);
    log_diagnostic("membership.deleted",
                   {
                       {"room_id", std::string{room_id}, false},
                       {"user_id", std::string{user_id}, false}
    });
    return true;
}

[[nodiscard]] auto upsert_invite(PersistentStore& store, PersistentInvite invite) -> bool
{
    auto const invite_state_json = serialize_invite_state_events_json(invite.invite_state_events_json);
    if (!invite_state_json.has_value())
    {
        log_diagnostic("invite.rejected", {
                                              {"room_id", invite.room_id,                      false},
                                              {"user_id", invite.user_id,                      false},
                                              {"reason",  "invite state serialization failed", false}
        });
        return false;
    }

    auto const existing = std::ranges::find_if(store.invites, [&](PersistentInvite const& current) {
        return current.room_id == invite.room_id && current.user_id == invite.user_id;
    });

    if (existing == store.invites.end())
    {
        if (!record_and_persist(
                store, record_statement("insert_invite", "INSERT INTO invites VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                                        {public_value(invite.room_id), public_value(invite.user_id),
                                         public_value(invite.sender_user_id), public_value(invite.event_id),
                                         sensitive_value(invite.signed_event_json), sensitive_value(*invite_state_json),
                                         public_value(std::to_string(invite.stream_ordering)),
                                         public_value(invite.resident_server)})))
        {
            log_diagnostic("invite.rejected", {
                                                  {"room_id", invite.room_id,                        false},
                                                  {"user_id", invite.user_id,                        false},
                                                  {"reason",  "persistence backend rejected insert", false}
            });
            return false;
        }
        log_diagnostic("invite.persisted", {
                                               {"room_id",         invite.room_id,                         false},
                                               {"user_id",         invite.user_id,                         false},
                                               {"event_id",        invite.event_id,                        false},
                                               {"stream_ordering", std::to_string(invite.stream_ordering), false}
        });
        store.invites.push_back(std::move(invite));
        return true;
    }

    if (!record_and_persist(
            store, record_statement(
                       "update_invite",
                       "UPDATE invites SET sender_user_id = $3, event_id = $4, signed_event_json = $5, "
                       "invite_state_json = $6, stream_ordering = $7, resident_server = $8 WHERE room_id = "
                       "$1 AND user_id = $2",
                       {public_value(invite.room_id), public_value(invite.user_id), public_value(invite.sender_user_id),
                        public_value(invite.event_id), sensitive_value(invite.signed_event_json),
                        sensitive_value(*invite_state_json), public_value(std::to_string(invite.stream_ordering)),
                        public_value(invite.resident_server)})))
    {
        log_diagnostic("invite.rejected", {
                                              {"room_id", invite.room_id,                        false},
                                              {"user_id", invite.user_id,                        false},
                                              {"reason",  "persistence backend rejected update", false}
        });
        return false;
    }

    *existing = std::move(invite);
    log_diagnostic("invite.updated", {
                                         {"room_id",  existing->room_id,  false},
                                         {"user_id",  existing->user_id,  false},
                                         {"event_id", existing->event_id, false}
    });
    return true;
}

[[nodiscard]] auto delete_invite(PersistentStore& store, std::string_view room_id, std::string_view user_id) -> bool
{
    auto const existing = std::ranges::find_if(store.invites, [&](PersistentInvite const& invite) {
        return invite.room_id == room_id && invite.user_id == user_id;
    });
    if (existing == store.invites.end())
    {
        return true;
    }

    if (!record_and_persist(store,
                            record_statement("delete_invite", "DELETE FROM invites WHERE room_id = $1 AND user_id = $2",
                                             {public_value(std::string{room_id}), public_value(std::string{user_id})})))
    {
        log_diagnostic("invite.rejected", {
                                              {"room_id", std::string{room_id},                  false},
                                              {"user_id", std::string{user_id},                  false},
                                              {"reason",  "persistence backend rejected delete", false}
        });
        return false;
    }

    store.invites.erase(existing);
    log_diagnostic("invite.deleted",
                   {
                       {"room_id", std::string{room_id}, false},
                       {"user_id", std::string{user_id}, false}
    });
    return true;
}

[[nodiscard]] auto find_invite(PersistentStore const& store, std::string_view room_id, std::string_view user_id)
    -> std::optional<PersistentInvite>
{
    auto const it = std::ranges::find_if(store.invites, [&](PersistentInvite const& invite) {
        return invite.room_id == room_id && invite.user_id == user_id;
    });
    return it == store.invites.end() ? std::nullopt : std::optional<PersistentInvite>{*it};
}

[[nodiscard]] auto store_room_with_membership(PersistentStore& store, PersistentRoom room,
                                              PersistentMembership membership) -> bool
{
    if (!sync_stream_has_write_reserve(store))
    {
        return false;
    }
    if (room.room_id != membership.room_id || room_exists(store, room.room_id) || membership_exists(store, membership))
    {
        log_diagnostic("room_membership.rejected",
                       {
                           {"room_id", room.room_id,                                       false},
                           {"creator", room.creator_user_id,                               false},
                           {"member",  membership.user_id,                                 false},
                           {"reason",  "room or membership shape is invalid or duplicate", false}
        });
        return false;
    }
    auto const room_statement = record_statement(
        "insert_room", "INSERT INTO rooms (room_id, creator_user_id, directory_public) VALUES ($1, $2, $3)",
        {
            {room.room_id,                             false},
            {room.creator_user_id,                     false},
            {room.directory_public ? "true" : "false", false}
    });
    auto const membership_statement =
        record_statement("insert_membership", "INSERT INTO membership VALUES ($1, $2, $3, $4)",
                         {
                             {membership.room_id,                         false},
                             {membership.user_id,                         false},
                             {membership.membership,                      false},
                             {std::to_string(membership.stream_ordering), false}
    });
    auto const statements = std::vector<PreparedStatement>{room_statement, membership_statement};
    if (!commit_persistent_transaction(store, statements))
    {
        log_diagnostic("room_membership.rejected", {
                                                       {"room_id", room.room_id,                               false},
                                                       {"creator", room.creator_user_id,                       false},
                                                       {"member",  membership.user_id,                         false},
                                                       {"reason",  "persistence backend rejected transaction", false}
        });
        return false;
    }
    log_diagnostic("room_membership.persisted", {
                                                    {"room_id",    room.room_id,          false},
                                                    {"creator",    room.creator_user_id,  false},
                                                    {"member",     membership.user_id,    false},
                                                    {"membership", membership.membership, false}
    });
    store.rooms.push_back(std::move(room));
    store.memberships.push_back(std::move(membership));
    note_membership_row_appended(store);
    return true;
}

auto rebuild_state_transition_index(PersistentStore& store) -> void
{
    store.state_transition_index.clear();
    store.state_transition_index.reserve(store.state_transitions.size() * 2U);
    for (auto index = std::size_t{0U}; index < store.state_transitions.size(); ++index)
    {
        auto const& transition = store.state_transitions[index];
        store.state_transition_index.emplace(state_transition_index_key(transition.room_id, transition.event_type,
                                                                        transition.state_key, transition.event_id),
                                             index);
    }
}

[[nodiscard]] auto find_state_transition(PersistentStore const& store, std::string_view room_id,
                                         std::string_view event_type, std::string_view state_key,
                                         std::string_view event_id) -> PersistentStateTransition const*
{
    auto const iterator =
        store.state_transition_index.find(state_transition_index_key(room_id, event_type, state_key, event_id));
    if (iterator == store.state_transition_index.end())
    {
        return nullptr;
    }
    return &store.state_transitions[iterator->second];
}

namespace
{

    // The key of `state_position_index`: the same NUL-separated form as the transition index. A
    // collision (an ID holding a NUL) only makes a lookup disagree with the row it reaches, which
    // is checked, so it costs a scan and never a wrong answer.
    [[nodiscard]] auto state_position_key(std::string_view room_id, std::string_view event_type,
                                          std::string_view state_key) -> std::string
    {
        auto key = std::string{};
        key.reserve(room_id.size() + event_type.size() + state_key.size() + 2U);
        key.append(room_id);
        key.push_back('\0');
        key.append(event_type);
        key.push_back('\0');
        key.append(state_key);
        return key;
    }

    [[nodiscard]] auto state_row_is(PersistentStateEvent const& row, std::string_view room_id,
                                    std::string_view event_type, std::string_view state_key) -> bool
    {
        return row.room_id == room_id && row.event_type == event_type && row.state_key == state_key;
    }

    // Adds the row just appended to `state` to the indexes, if they were in step before it. If they
    // were not (something edited the vector behind the store's back) they stay out of step, so
    // lookups scan, until the next rebuild.
    auto note_state_row_appended(PersistentStore& store) -> void
    {
        if (store.state.empty() || store.state_indexed_rows + 1U != store.state.size())
        {
            return;
        }
        auto const position = store.state.size() - 1U;
        auto const& row = store.state[position];
        store.state_position_index.emplace(state_position_key(row.room_id, row.event_type, row.state_key), position);
        store.state_room_index[row.room_id].push_back(position);
        store.state_indexed_rows = store.state.size();
    }

} // namespace

auto rebuild_state_index(PersistentStore& store) -> void
{
    store.state_position_index.clear();
    store.state_room_index.clear();
    store.state_position_index.reserve(store.state.size());
    for (auto position = std::size_t{0U}; position < store.state.size(); ++position)
    {
        auto const& row = store.state[position];
        store.state_position_index.emplace(state_position_key(row.room_id, row.event_type, row.state_key), position);
        store.state_room_index[row.room_id].push_back(position);
    }
    store.state_indexed_rows = store.state.size();
}

[[nodiscard]] auto find_current_state_event_id(PersistentStore const& store, std::string_view room_id,
                                               std::string_view event_type, std::string_view state_key)
    -> std::optional<std::string>
{
    if (store.state_indexed_rows == store.state.size())
    {
        auto const entry = store.state_position_index.find(state_position_key(room_id, event_type, state_key));
        if (entry == store.state_position_index.end())
        {
            return std::nullopt;
        }
        if (entry->second < store.state.size() &&
            state_row_is(store.state[entry->second], room_id, event_type, state_key))
        {
            return store.state[entry->second].event_id;
        }
    }
    for (auto const& row : store.state)
    {
        if (state_row_is(row, room_id, event_type, state_key))
        {
            return row.event_id;
        }
    }
    return std::nullopt;
}

auto for_each_room_state_row(PersistentStore const& store, std::string_view room_id,
                             std::function<void(PersistentStateEvent const&)> const& visit) -> void
{
    if (store.state_indexed_rows == store.state.size())
    {
        auto const entry = store.state_room_index.find(std::string{room_id});
        if (entry == store.state_room_index.end())
        {
            return;
        }
        auto const names_the_room = [&](std::size_t position) {
            return position < store.state.size() && store.state[position].room_id == room_id;
        };
        if (std::ranges::all_of(entry->second, names_the_room))
        {
            for (auto const position : entry->second)
            {
                visit(store.state[position]);
            }
            return;
        }
    }
    for (auto const& row : store.state)
    {
        if (row.room_id == room_id)
        {
            visit(row);
        }
    }
}

auto rebuild_membership_index(PersistentStore& store) -> void
{
    store.membership_room_index.clear();
    for (auto position = std::size_t{0U}; position < store.memberships.size(); ++position)
    {
        store.membership_room_index[store.memberships[position].room_id].push_back(position);
    }
    store.membership_indexed_rows = store.memberships.size();
}

auto for_each_room_membership_row(PersistentStore const& store, std::string_view room_id,
                                  std::function<void(PersistentMembership const&)> const& visit) -> void
{
    if (store.membership_indexed_rows == store.memberships.size())
    {
        auto const entry = store.membership_room_index.find(std::string{room_id});
        if (entry == store.membership_room_index.end())
        {
            return;
        }
        auto const names_the_room = [&](std::size_t position) {
            return position < store.memberships.size() && store.memberships[position].room_id == room_id;
        };
        if (std::ranges::all_of(entry->second, names_the_room))
        {
            for (auto const position : entry->second)
            {
                visit(store.memberships[position]);
            }
            return;
        }
    }
    for (auto const& row : store.memberships)
    {
        if (row.room_id == room_id)
        {
            visit(row);
        }
    }
}

namespace
{

    struct RedactionShape final
    {
        bool is_redaction{false};
        std::vector<std::string> targets{};
    };

    // CSAZ-11. Whether `json` is an m.room.redaction event and which event IDs it names. A
    // redaction names its target in `redacts` at the top level (room versions before 11) or in
    // `content` (11 and later); both places are recorded, and the redaction reconciler keeps only
    // the one the room version uses. Most events fail the substring test and are never parsed.
    [[nodiscard]] auto redaction_shape_of(std::string_view json) -> RedactionShape
    {
        auto shape = RedactionShape{};
        if (json.find("m.room.redaction") == std::string_view::npos)
        {
            return shape;
        }
        auto const parsed = canonicaljson::parse_lossless(json);
        auto const* object = parsed.error == canonicaljson::ParseError::none
                                 ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                                 : nullptr;
        if (object == nullptr)
        {
            return shape;
        }
        auto const string_in = [](canonicaljson::Object const& holder, std::string_view key) -> std::string const* {
            for (auto const& member : holder)
            {
                if (member.key == key)
                {
                    return std::get_if<std::string>(&member.value->storage());
                }
            }
            return nullptr;
        };
        auto const* type = string_in(*object, "type");
        if (type == nullptr || *type != "m.room.redaction")
        {
            return shape;
        }
        shape.is_redaction = true;
        if (auto const* top_level = string_in(*object, "redacts"); top_level != nullptr && !top_level->empty())
        {
            shape.targets.push_back(*top_level);
        }
        for (auto const& member : *object)
        {
            if (member.key != "content")
            {
                continue;
            }
            if (auto const* content = std::get_if<canonicaljson::Object>(&member.value->storage()); content != nullptr)
            {
                if (auto const* in_content = string_in(*content, "redacts");
                    in_content != nullptr && !in_content->empty() &&
                    std::ranges::find(shape.targets, *in_content) == shape.targets.end())
                {
                    shape.targets.push_back(*in_content);
                }
            }
        }
        return shape;
    }

    // Records a newly stored event in the redaction bookkeeping. A redaction starts out withheld.
    auto note_event_for_redactions(PersistentStore& store, PersistentEvent const& event) -> void
    {
        auto const shape = redaction_shape_of(event.json);
        if (!shape.is_redaction)
        {
            return;
        }
        store.redactions.withheld.insert(event.event_id);
        for (auto const& target : shape.targets)
        {
            auto& ids = store.redactions.by_target[target];
            if (std::ranges::find(ids, event.event_id) == ids.end())
            {
                ids.push_back(event.event_id);
            }
        }
    }

    auto notify_redaction_observer(PersistentStore& store, std::string const& event_id) -> void
    {
        if (store.redaction_observer)
        {
            store.redaction_observer(store, event_id);
        }
    }

} // namespace

[[nodiscard]] auto store_event(PersistentStore& store, PersistentEvent event) -> bool
{
    if (event_exists(store, event.event_id))
    {
        return false;
    }
    auto statements = std::vector<PreparedStatement>{
        record_statement("insert_event",
                         "INSERT INTO events (event_id, room_id, sender_user_id, json, depth, stream_ordering, status) "
                         "VALUES ($1, $2, $3, $4, $5, $6, $7)",
                         {{event.event_id, false},
                           {event.room_id, false},
                           {event.sender_user_id, false},
                           {event.json, true},
                           {std::to_string(event.depth), false},
                           {std::to_string(event.stream_ordering), false},
                           {event.status, false}}
                         )
    };
    append_event_graph_statements(statements, event);
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    append_event_graph_rows(store, event);
    note_event_for_redactions(store, event);
    auto stored_event_id = event.event_id;
    std::ignore = store.events.insert(std::move(event));
    notify_redaction_observer(store, stored_event_id);
    return true;
}

[[nodiscard]] auto store_state(PersistentStore& store, PersistentStateEvent state) -> bool
{
    if (!state_matches_persisted_event(store, state))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.state, [&state](PersistentStateEvent const& current) {
        return current.room_id == state.room_id && current.event_type == state.event_type &&
               current.state_key == state.state_key;
    });
    // State resolution and repair paths can re-apply a state event that is
    // already current. Treat that as an idempotent no-op.
    if (existing != store.state.end() && existing->event_id == state.event_id)
    {
        return true;
    }
    auto prepared =
        prepare_current_state(std::move(state), existing != store.state.end() ? existing->event_id : std::string{});
    if (!commit_persistent_transaction(store, prepared.statements))
    {
        return false;
    }
    apply_current_state(store, prepared);
    return true;
}

[[nodiscard]] auto state_matches_stored_event(PersistentStore const& store, PersistentStateEvent const& state) -> bool
{
    return state_matches_persisted_event(store, state);
}

[[nodiscard]] auto prepare_current_state(PersistentStateEvent state, std::string previous_event_id)
    -> PreparedCurrentState
{
    auto statements = std::vector<PreparedStatement>{};
    if (!previous_event_id.empty())
    {
        statements.push_back(record_statement(
            "upsert_state",
            "UPDATE current_state SET event_id = $4 WHERE room_id = $1 AND event_type = $2 AND state_key = $3",
            {
                {state.room_id,    false},
                {state.event_type, false},
                {state.state_key,  false},
                {state.event_id,   false}
        }));
    }
    else
    {
        statements.push_back(record_statement(
            "insert_state", "INSERT INTO current_state VALUES ($1, $2, $3, $4)",
            {
                {state.room_id,    false},
                {state.event_type, false},
                {state.state_key,  false},
                {state.event_id,   false}
        }));
    }
    // ADR-0064 phase B1: state resolution over forward extremities can make
    // an event current again after it was previously superseded (spec
    // requires a resolution that reverts a key to an older event be
    // delivered like any other state change). state_transitions' primary key
    // is (room_id, event_type, state_key, event_id) — the same event_id
    // becoming current a second time is a fresh transition to record, not a
    // duplicate row, so this is an upsert keyed on that same tuple rather
    // than a bare INSERT (which would violate the primary key and silently
    // fail the whole commit the second time any event_id is reactivated).
    statements.push_back(
        record_statement("upsert_state_transition",
                         "INSERT INTO state_transitions (room_id, event_type, state_key, event_id, previous_event_id) "
                         "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (room_id, event_type, state_key, event_id) "
                         "DO UPDATE SET previous_event_id = excluded.previous_event_id",
                         {
                             {state.room_id,     false},
                             {state.event_type,  false},
                             {state.state_key,   false},
                             {state.event_id,    false},
                             {previous_event_id, false}
    }));
    return {std::move(state), std::move(previous_event_id), std::move(statements)};
}

auto apply_current_state(PersistentStore& store, PreparedCurrentState const& prepared) -> void
{
    auto const& state = prepared.state;
    auto const& previous_event_id = prepared.previous_event_id;
    auto const existing = std::ranges::find_if(store.state, [&state](PersistentStateEvent const& current) {
        return current.room_id == state.room_id && current.event_type == state.event_type &&
               current.state_key == state.state_key;
    });
    if (existing != store.state.end())
    {
        existing->event_id = state.event_id;
    }
    else
    {
        store.state.push_back(state);
        note_state_row_appended(store);
    }
    // Mirror the same upsert semantics into the in-memory index: update the
    // existing row in place when this (room, type, key, event_id) tuple was
    // already indexed (a reactivation), rather than pushing a second entry
    // that state_transition_index::emplace would silently ignore, leaving
    // the index pointing at the stale previous_event_id.
    auto const transition_key =
        state_transition_index_key(state.room_id, state.event_type, state.state_key, state.event_id);
    if (auto const index_it = store.state_transition_index.find(transition_key);
        index_it != store.state_transition_index.end() && index_it->second < store.state_transitions.size())
    {
        store.state_transitions[index_it->second].previous_event_id = previous_event_id;
    }
    else
    {
        store.state_transitions.push_back(
            {state.room_id, state.event_type, state.state_key, state.event_id, previous_event_id});
        store.state_transition_index.emplace(transition_key, store.state_transitions.size() - 1U);
    }
}

[[nodiscard]] auto prepare_store_event_with_state(PersistentStore& store, PersistentEvent event,
                                                  std::optional<PersistentStateEvent> state,
                                                  std::optional<MembershipProjection> membership)
    -> std::optional<PreparedStateUpdate>
{
    if (!sync_stream_has_write_reserve(store))
    {
        return std::nullopt;
    }
    // DB-4: a projection belongs to the member event it is stored with.
    if (membership.has_value() &&
        (!state.has_value() || state->event_type != "m.room.member" || state->state_key != membership->user_id ||
         !membership_projection_is_valid(*membership)))
    {
        log_diagnostic("event_state.rejected",
                       {
                           {"event_id", event.event_id,                                   false},
                           {"room_id",  event.room_id,                                    false},
                           {"reason",   "membership projection does not match the event", false}
        });
        return std::nullopt;
    }
    if (event_exists(store, event.event_id) || (state.has_value() && !state_matches_event(event, *state)))
    {
        log_diagnostic("event_state.rejected", {
                                                   {"event_id",  event.event_id,                                  false},
                                                   {"room_id",   event.room_id,                                   false},
                                                   {"sender",    event.sender_user_id,                            false},
                                                   {"has_state", state.has_value() ? "true" : "false",            false},
                                                   {"reason",    "duplicate event or state does not match event", false}
        });
        return std::nullopt;
    }

    auto update = PreparedStateUpdate{};
    update.event = std::move(event);
    update.state = std::move(state);
    update.statements.push_back(record_statement("insert_event",
                                                 "INSERT INTO events (event_id, room_id, sender_user_id, json, depth, "
                                                 "stream_ordering, status) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                                                 {
                                                     {update.event.event_id,                        false},
                                                     {update.event.room_id,                         false},
                                                     {update.event.sender_user_id,                  false},
                                                     {update.event.json,                            true },
                                                     {std::to_string(update.event.depth),           false},
                                                     {std::to_string(update.event.stream_ordering), false},
                                                     {update.event.status,                          false}
    }));
    append_event_graph_statements(update.statements, update.event);

    if (update.state.has_value())
    {
        auto const existing = std::ranges::find_if(store.state, [&update](PersistentStateEvent const& current) {
            return current.room_id == update.state->room_id && current.event_type == update.state->event_type &&
                   current.state_key == update.state->state_key;
        });
        update.state_already_existed = existing != store.state.end();
        // Derive the predecessor from the event's own graph rather than assuming the
        // local arrival-time current_state was the previous event. On forks the two
        // can diverge, and Matrix v1.19's unsigned.replaces_state must describe the
        // event's actual predecessor.
        auto const previous_event_id = find_predecessor_state_event_id(
            store, update.state->room_id, update.state->event_type, update.state->state_key,
            update.event.prev_event_ids, update.event.auth_event_ids);
        if (update.state_already_existed)
        {
            update.statements.push_back(record_statement(
                "upsert_state",
                "UPDATE current_state SET event_id = $4 WHERE room_id = $1 AND event_type = $2 AND state_key = $3",
                {
                    {update.state->room_id,    false},
                    {update.state->event_type, false},
                    {update.state->state_key,  false},
                    {update.state->event_id,   false}
            }));
        }
        else
        {
            update.statements.push_back(record_statement("insert_state",
                                                         "INSERT INTO current_state VALUES ($1, $2, $3, $4)",
                                                         {
                                                             {update.state->room_id,    false},
                                                             {update.state->event_type, false},
                                                             {update.state->state_key,  false},
                                                             {update.state->event_id,   false}
            }));
        }
        update.statements.push_back(record_statement("insert_state_transition",
                                                     "INSERT INTO state_transitions (room_id, event_type, state_key, "
                                                     "event_id, previous_event_id) VALUES ($1, $2, $3, $4, $5)",
                                                     {
                                                         {update.state->room_id,    false},
                                                         {update.state->event_type, false},
                                                         {update.state->state_key,  false},
                                                         {update.state->event_id,   false},
                                                         {previous_event_id,        false}
        }));
        update.previous_event_id = previous_event_id;
    }
    if (membership.has_value())
    {
        if (!append_membership_projection_statements(update.statements, update.event.room_id, *membership))
        {
            return std::nullopt;
        }
        update.membership = std::move(membership);
    }

    return update;
}

auto apply_store_event_with_state(PersistentStore& store, PreparedStateUpdate const& update) -> void
{
    // Idempotent duplicate guard: a concurrent prepare/commit for the same event
    // may have raced us to the backend. If the event is already mirrored in memory,
    // drop this application so the in-memory row and its indexes stay as first stored.
    if (event_exists(store, update.event.event_id))
    {
        return;
    }

    log_diagnostic("event_state.persisted",
                   {
                       {"event_id",        update.event.event_id,                        false},
                       {"room_id",         update.event.room_id,                         false},
                       {"sender",          update.event.sender_user_id,                  false},
                       {"depth",           std::to_string(update.event.depth),           false},
                       {"stream_ordering", std::to_string(update.event.stream_ordering), false},
                       {"has_state",       update.state.has_value() ? "true" : "false",  false}
    });
    append_event_graph_rows(store, update.event);
    std::ignore = store.events.insert(update.event);
    note_event_for_redactions(store, update.event);
    if (update.state.has_value())
    {
        auto const existing = std::ranges::find_if(store.state, [&update](PersistentStateEvent const& current) {
            return current.room_id == update.state->room_id && current.event_type == update.state->event_type &&
                   current.state_key == update.state->state_key;
        });
        if (existing != store.state.end())
        {
            existing->event_id = update.state->event_id;
        }
        else
        {
            store.state.push_back(*update.state);
            note_state_row_appended(store);
        }
        store.state_transitions.push_back({update.state->room_id, update.state->event_type, update.state->state_key,
                                           update.state->event_id, update.previous_event_id});
        store.state_transition_index.emplace(state_transition_index_key(update.state->room_id, update.state->event_type,
                                                                        update.state->state_key,
                                                                        update.state->event_id),
                                             store.state_transitions.size() - 1U);
    }
    if (update.membership.has_value())
    {
        apply_membership_projection(store, update.event.room_id, *update.membership);
    }
    // Last, so the observer sees the event with its state already mirrored.
    notify_redaction_observer(store, update.event.event_id);
}

[[nodiscard]] auto store_event_with_state(PersistentStore& store, PersistentEvent event,
                                          std::optional<PersistentStateEvent> state,
                                          std::optional<MembershipProjection> membership) -> bool
{
    auto prepared = prepare_store_event_with_state(store, std::move(event), std::move(state), std::move(membership));
    if (!prepared.has_value())
    {
        return false;
    }
    if (!commit_persistent_transaction(store, prepared->statements))
    {
        log_diagnostic("event_state.rejected", {
                                                   {"event_id",  prepared->event.event_id,                       false},
                                                   {"room_id",   prepared->event.room_id,                        false},
                                                   {"sender",    prepared->event.sender_user_id,                 false},
                                                   {"has_state", prepared->state.has_value() ? "true" : "false", false},
                                                   {"reason",    "persistence backend rejected transaction",     false}
        });
        return false;
    }
    apply_store_event_with_state(store, *prepared);
    return true;
}

namespace
{

    // Composite key for (event_type, state_key), used to compare and merge
    // state group rows. Same NUL-separator convention as
    // state_transition_index_key above -- Matrix event type/state key never
    // contain embedded NUL.
    [[nodiscard]] auto state_group_entry_key(std::string_view event_type, std::string_view state_key) -> std::string
    {
        auto key = std::string{};
        key.reserve(event_type.size() + state_key.size() + 1U);
        key.append(event_type);
        key.push_back('\0');
        key.append(state_key);
        return key;
    }

    [[nodiscard]] auto to_state_group_map(std::vector<PersistentStateGroupStateEntry> const& entries)
        -> std::unordered_map<std::string, std::string>
    {
        auto map = std::unordered_map<std::string, std::string>{};
        map.reserve(entries.size());
        for (auto const& entry : entries)
        {
            map.emplace(state_group_entry_key(entry.event_type, entry.state_key), entry.event_id);
        }
        return map;
    }

    [[nodiscard]] auto find_persistent_state_group(PersistentStore const& store, std::string_view state_group_id)
        -> PersistentStateGroup const*
    {
        auto const iterator = store.state_groups.find(state_group_id);
        return iterator == store.state_groups.end() ? nullptr : &*iterator;
    }

    [[nodiscard]] auto event_status_is_valid(std::string_view status) noexcept -> bool
    {
        return status == "accepted" || status == "soft_failed" || status == "rejected" || status == "outlier";
    }

} // namespace

[[nodiscard]] auto find_state_group(PersistentStore const& store, std::string_view state_group_id)
    -> std::optional<PersistentStateGroup>
{
    auto const* group = find_persistent_state_group(store, state_group_id);
    return group == nullptr ? std::nullopt : std::optional<PersistentStateGroup>{*group};
}

[[nodiscard]] auto read_state_group_full_state(PersistentStore const& store, std::string_view state_group_id)
    -> std::optional<std::vector<PersistentStateGroupStateEntry>>
{
    // Walk parent links back to the snapshot, collecting the chain newest
    // (state_group_id itself) first. Bounded to max_state_group_delta_depth + 1
    // groups and cycle-detected; a missing group, a cycle, or an over-long
    // chain fails closed rather than returning partial state.
    auto chain = std::vector<PersistentStateGroup const*>{};
    auto visited = std::unordered_set<std::string>{};
    auto current = std::string{state_group_id};
    for (;;)
    {
        if (!visited.insert(current).second)
        {
            return std::nullopt; // cycle
        }
        auto const* group = find_persistent_state_group(store, current);
        if (group == nullptr)
        {
            return std::nullopt; // missing group
        }
        chain.push_back(group);
        if (!group->parent_state_group_id.has_value())
        {
            break; // reached the snapshot
        }
        if (chain.size() > events::max_state_group_delta_depth)
        {
            return std::nullopt; // over-long chain
        }
        current = *group->parent_state_group_id;
    }

    auto seen = std::unordered_set<std::string>{};
    auto result = std::vector<PersistentStateGroupStateEntry>{};
    for (auto const* group : chain) // newest (target) first, snapshot last
    {
        for (auto const& entry : store.state_group_state.entries_of(group->state_group_id))
        {
            if (seen.insert(state_group_entry_key(entry.event_type, entry.state_key)).second)
            {
                result.push_back(entry);
            }
        }
    }
    return result;
}

[[nodiscard]] auto create_or_reuse_state_group(PersistentStore& store, std::string_view room_id,
                                               std::string_view new_state_group_id,
                                               std::optional<std::string> const& parent_state_group_id,
                                               std::vector<PersistentStateGroupStateEntry> const& full_state)
    -> std::optional<std::string>
{
    auto const prepared = prepare_state_group(store, room_id, new_state_group_id, parent_state_group_id, full_state);
    if (!prepared.has_value())
    {
        return std::nullopt;
    }
    if (!commit_persistent_transaction(store, prepared->statements))
    {
        return std::nullopt;
    }
    apply_state_group(store, *prepared);
    return prepared->state_group_id;
}

[[nodiscard]] auto prepare_state_group(PersistentStore const& store, std::string_view room_id,
                                       std::string_view new_state_group_id,
                                       std::optional<std::string> const& parent_state_group_id,
                                       std::vector<PersistentStateGroupStateEntry> const& full_state)
    -> std::optional<PreparedStateGroup>
{
    auto const requested_map = to_state_group_map(full_state);

    auto parent_depth = std::uint32_t{0U};
    auto parent_map = std::unordered_map<std::string, std::string>{};
    if (parent_state_group_id.has_value())
    {
        auto const* parent_group = find_persistent_state_group(store, *parent_state_group_id);
        auto const parent_full = read_state_group_full_state(store, *parent_state_group_id);
        if (parent_group == nullptr || !parent_full.has_value())
        {
            return std::nullopt; // fail closed: cannot verify the parent
        }
        parent_depth = parent_group->delta_depth;
        parent_map = to_state_group_map(*parent_full);
        if (requested_map == parent_map)
        {
            // Unchanged: reuse the parent group, writing nothing.
            auto reused = PreparedStateGroup{};
            reused.state_group_id = *parent_state_group_id;
            return reused;
        }
    }

    auto write_snapshot =
        !parent_state_group_id.has_value() || (parent_depth + 1U) > events::max_state_group_delta_depth;
    if (!write_snapshot)
    {
        for (auto const& [key, unused_event_id] : parent_map)
        {
            std::ignore = unused_event_id;
            if (!requested_map.contains(key))
            {
                write_snapshot = true; // deltas never encode deletions
                break;
            }
        }
    }

    auto rows_to_persist = std::vector<PersistentStateGroupStateEntry>{};
    if (write_snapshot)
    {
        rows_to_persist = full_state;
    }
    else
    {
        for (auto const& entry : full_state)
        {
            auto const key = state_group_entry_key(entry.event_type, entry.state_key);
            auto const parent_it = parent_map.find(key);
            if (parent_it == parent_map.end() || parent_it->second != entry.event_id)
            {
                rows_to_persist.push_back(entry);
            }
        }
    }

    auto const new_depth = write_snapshot ? std::uint32_t{0U} : parent_depth + 1U;
    auto const parent_column_value = write_snapshot ? std::string{} : *parent_state_group_id;

    auto prepared = PreparedStateGroup{};
    prepared.state_group_id = std::string{new_state_group_id};
    prepared.group = PersistentStateGroup{std::string{new_state_group_id}, std::string{room_id},
                                          write_snapshot ? std::nullopt : parent_state_group_id, new_depth};
    prepared.statements.push_back(
        record_statement("insert_state_group",
                         "INSERT INTO state_groups (state_group_id, room_id, parent_state_group_id, delta_depth) "
                         "VALUES ($1, $2, $3, $4)",
                         {public_value(new_state_group_id), public_value(room_id), public_value(parent_column_value),
                          public_value(std::to_string(new_depth))}));
    for (auto row : rows_to_persist)
    {
        prepared.statements.push_back(record_statement("insert_state_group_state",
                                                       "INSERT INTO state_group_state VALUES ($1, $2, $3, $4)",
                                                       {public_value(new_state_group_id), public_value(row.event_type),
                                                        public_value(row.state_key), public_value(row.event_id)}));
        row.state_group_id = std::string{new_state_group_id};
        prepared.rows.push_back(std::move(row));
    }
    return prepared;
}

auto apply_state_group(PersistentStore& store, PreparedStateGroup const& prepared) -> void
{
    if (!prepared.group.has_value())
    {
        return; // the parent was reused
    }
    std::ignore = store.state_groups.insert(*prepared.group);
    store.state_group_state.insert_all(prepared.rows);
}

[[nodiscard]] auto set_event_state_group(PersistentStore& store, std::string_view event_id,
                                         std::string_view state_group_id) -> bool
{
    auto statement = prepare_event_state_group(event_id, state_group_id);
    if (!statement.has_value() || !record_and_persist(store, std::move(*statement)))
    {
        return false;
    }
    apply_event_state_group(store, event_id, state_group_id);
    return true;
}

[[nodiscard]] auto prepare_event_state_group(std::string_view event_id, std::string_view state_group_id)
    -> std::optional<PreparedStatement>
{
    if (event_id.empty() || state_group_id.empty())
    {
        return std::nullopt;
    }
    return record_statement("upsert_event_state_group",
                            "INSERT INTO event_state_groups VALUES ($1, $2) ON CONFLICT "
                            "(event_id) DO UPDATE SET state_group_id = $2",
                            {public_value(event_id), public_value(state_group_id)});
}

auto apply_event_state_group(PersistentStore& store, std::string_view event_id, std::string_view state_group_id) -> void
{
    store.event_state_groups.assign(event_id, state_group_id);
}

[[nodiscard]] auto find_event_state_group(PersistentStore const& store, std::string_view event_id)
    -> std::optional<std::string>
{
    auto const group_id = store.event_state_groups.state_group_of(event_id);
    return group_id.has_value() ? std::optional<std::string>{std::string{*group_id}} : std::nullopt;
}

[[nodiscard]] auto update_forward_extremities(PersistentStore& store, std::string_view room_id,
                                              std::string_view event_id, std::vector<std::string> const& prev_event_ids,
                                              bool accepted) -> bool
{
    if (!accepted)
    {
        return true; // soft-failed/rejected events never touch extremities
    }
    if (room_id.empty() || event_id.empty())
    {
        return false;
    }
    if (!commit_persistent_transaction(store, prepare_forward_extremities_update(room_id, event_id, prev_event_ids)))
    {
        return false;
    }
    apply_forward_extremities_update(store, room_id, event_id, prev_event_ids);
    return true;
}

[[nodiscard]] auto prepare_forward_extremities_update(std::string_view room_id, std::string_view event_id,
                                                      std::vector<std::string> const& replaced_event_ids)
    -> std::vector<PreparedStatement>
{
    if (room_id.empty() || event_id.empty())
    {
        return {};
    }
    auto statements = std::vector<PreparedStatement>{};
    for (auto const& replaced_event_id : replaced_event_ids)
    {
        statements.push_back(record_statement("delete_forward_extremity",
                                              "DELETE FROM forward_extremities WHERE room_id = $1 AND event_id = $2",
                                              {public_value(room_id), public_value(replaced_event_id)}));
    }
    statements.push_back(
        record_statement("insert_forward_extremity",
                         "INSERT INTO forward_extremities VALUES ($1, $2) ON CONFLICT (room_id, event_id) DO NOTHING",
                         {public_value(room_id), public_value(event_id)}));
    return statements;
}

auto apply_forward_extremities_update(PersistentStore& store, std::string_view room_id, std::string_view event_id,
                                      std::vector<std::string> const& replaced_event_ids) -> void
{
    for (auto const& replaced_event_id : replaced_event_ids)
    {
        std::erase_if(store.forward_extremities,
                      [room_id, &replaced_event_id](PersistentForwardExtremity const& extremity) {
                          return extremity.room_id == room_id && extremity.event_id == replaced_event_id;
                      });
    }
    if (!std::ranges::any_of(store.forward_extremities,
                             [room_id, event_id](PersistentForwardExtremity const& extremity) {
                                 return extremity.room_id == room_id && extremity.event_id == event_id;
                             }))
    {
        store.forward_extremities.push_back({std::string{room_id}, std::string{event_id}});
    }
}

[[nodiscard]] auto find_forward_extremities(PersistentStore const& store, std::string_view room_id)
    -> std::vector<std::string>
{
    auto result = std::vector<std::string>{};
    for (auto const& extremity : store.forward_extremities)
    {
        if (extremity.room_id == room_id)
        {
            result.push_back(extremity.event_id);
        }
    }
    return result;
}

[[nodiscard]] auto set_event_status(PersistentStore& store, std::string_view event_id, std::string_view status) -> bool
{
    if (!event_status_is_valid(status))
    {
        return false;
    }
    auto const existing = store.events.find(event_id);
    if (existing == store.events.end())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("update_event_status", "UPDATE events SET status = $2 WHERE event_id = $1",
                                             {public_value(event_id), public_value(status)})))
    {
        return false;
    }
    store.events.modify(existing, [status](PersistentEvent& event) {
        event.status = std::string{status};
    });
    return true;
}

auto rebuild_redaction_state(PersistentStore& store) -> void
{
    store.redactions = RedactionState{};
    for (auto const& event : store.events)
    {
        note_event_for_redactions(store, event);
    }
}

[[nodiscard]] auto redactions_naming(PersistentStore const& store, std::string_view target_event_id)
    -> std::vector<std::string>
{
    auto const it = store.redactions.by_target.find(std::string{target_event_id});
    return it == store.redactions.by_target.end() ? std::vector<std::string>{} : it->second;
}

[[nodiscard]] auto redaction_is_withheld(PersistentStore const& store, std::string_view event_id) -> bool
{
    return store.redactions.withheld.contains(std::string{event_id});
}

[[nodiscard]] auto applied_redaction_of(PersistentStore const& store, std::string_view target_event_id)
    -> std::optional<std::string>
{
    auto const it = store.redactions.applied_by_target.find(std::string{target_event_id});
    if (it == store.redactions.applied_by_target.end())
    {
        return std::nullopt;
    }
    return it->second;
}

auto mark_redaction_applied(PersistentStore& store, std::string_view redaction_event_id,
                            std::string_view target_event_id) -> void
{
    store.redactions.withheld.erase(std::string{redaction_event_id});
    store.redactions.applied_by_target.try_emplace(std::string{target_event_id}, std::string{redaction_event_id});
}

[[nodiscard]] auto replace_event_json(PersistentStore& store, std::string_view event_id, std::string json) -> bool
{
    auto const existing = store.events.find(event_id);
    if (existing == store.events.end())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("update_event_json", "UPDATE events SET json = $2 WHERE event_id = $1",
                                             {
                                                 public_value(event_id), {json, true}
    })))
    {
        return false;
    }
    store.events.modify(existing, [&json](PersistentEvent& event) {
        event.json = std::move(json);
    });
    return true;
}

[[nodiscard]] auto find_event_status(PersistentStore const& store, std::string_view event_id)
    -> std::optional<std::string>
{
    auto const existing = store.events.find(event_id);
    return existing == store.events.end() ? std::nullopt : std::optional<std::string>{existing->status};
}

[[nodiscard]] auto store_device_key(PersistentStore& store, PersistentDeviceKey key) -> bool
{
    if (!key_payload_is_valid(key.json))
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement(
                "upsert_device_key",
                "INSERT INTO device_keys VALUES ($1, $2, $3) ON CONFLICT (user_id, device_id) DO UPDATE SET json = $3",
                {public_value(key.user_id), public_value(key.device_id), sensitive_value(key.json)})))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.device_keys, [&key](PersistentDeviceKey const& current) {
        return current.user_id == key.user_id && current.device_id == key.device_id;
    });
    if (existing != store.device_keys.end())
    {
        existing->json = std::move(key.json);
        return true;
    }
    store.device_keys.push_back(std::move(key));
    return true;
}

[[nodiscard]] auto find_device_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id)
    -> std::optional<PersistentDeviceKey>
{
    auto const existing = std::ranges::find_if(store.device_keys, [user_id, device_id](PersistentDeviceKey const& key) {
        return key.user_id == user_id && key.device_id == device_id;
    });
    return existing == store.device_keys.end() ? std::nullopt : std::optional<PersistentDeviceKey>{*existing};
}

[[nodiscard]] auto store_one_time_key(PersistentStore& store, PersistentOneTimeKey key) -> bool
{
    if (!key_payload_is_valid(key.json) || key.key_id.empty())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("upsert_one_time_key",
                                             "INSERT INTO one_time_keys VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, "
                                             "device_id, key_id) DO UPDATE SET json = $4",
                                             {public_value(key.user_id), public_value(key.device_id),
                                              public_value(key.key_id), sensitive_value(key.json)})))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.one_time_keys, [&key](PersistentOneTimeKey const& current) {
        return current.user_id == key.user_id && current.device_id == key.device_id && current.key_id == key.key_id;
    });
    if (existing != store.one_time_keys.end())
    {
        existing->json = std::move(key.json);
        return true;
    }
    store.one_time_keys.push_back(std::move(key));
    return true;
}

[[nodiscard]] auto claim_one_time_key(PersistentStore& store, std::string_view user_id, std::string_view device_id,
                                      std::string_view algorithm) -> std::optional<PersistentOneTimeKey>
{
    auto const prefix = std::string{algorithm} + ':';
    auto const existing = std::ranges::find_if(
        store.one_time_keys, [user_id, device_id, algorithm, &prefix](PersistentOneTimeKey const& key) {
            return key.user_id == user_id && key.device_id == device_id &&
                   (algorithm.empty() || key.key_id.starts_with(prefix));
        });
    if (existing == store.one_time_keys.end())
    {
        return std::nullopt;
    }
    auto claimed = *existing;
    if (!record_and_persist(store, record_statement("delete_one_time_key",
                                                    "DELETE FROM one_time_keys WHERE user_id = $1 AND device_id = $2 "
                                                    "AND key_id = $3",
                                                    {public_value(claimed.user_id), public_value(claimed.device_id),
                                                     public_value(claimed.key_id)})))
    {
        return std::nullopt;
    }
    store.one_time_keys.erase(existing);
    return claimed;
}

[[nodiscard]] auto store_fallback_key(PersistentStore& store, PersistentFallbackKey key) -> bool
{
    if (!key_payload_is_valid(key.json) || key.key_id.empty())
    {
        return false;
    }
    // Spec v1.19 (POST /keys/upload, `fallback_keys`): "There can only be at
    // most one key per algorithm uploaded, and the server will only persist
    // one key per algorithm." A fallback key of algorithm A therefore replaces
    // every other fallback key of A held for the same user and device (the
    // algorithm is the key id up to and including its first ':'). The deletes
    // and the insert commit as one transaction so a failure leaves the
    // previous key in place, and the in-memory mirror changes only afterwards.
    auto const colon = key.key_id.find(':');
    auto const algorithm_prefix = colon == std::string::npos ? key.key_id : key.key_id.substr(0U, colon + 1U);
    auto const same_algorithm = [&key, &algorithm_prefix](PersistentFallbackKey const& current) {
        return current.user_id == key.user_id && current.device_id == key.device_id &&
               current.key_id.starts_with(algorithm_prefix);
    };
    auto statements = std::vector<PreparedStatement>{};
    for (auto const& current : store.fallback_keys)
    {
        if (same_algorithm(current) && current.key_id != key.key_id)
        {
            statements.push_back(record_statement(
                "delete_superseded_fallback_key",
                "DELETE FROM fallback_keys WHERE user_id = $1 AND device_id = $2 "
                "AND key_id = $3",
                {public_value(current.user_id), public_value(current.device_id), public_value(current.key_id)}));
        }
    }
    statements.push_back(record_statement(
        "upsert_fallback_key",
        "INSERT INTO fallback_keys VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, "
        "device_id, key_id) DO UPDATE SET json = $4",
        {public_value(key.user_id), public_value(key.device_id), public_value(key.key_id), sensitive_value(key.json)}));
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    std::erase_if(store.fallback_keys, [&](PersistentFallbackKey const& current) {
        return same_algorithm(current) && current.key_id != key.key_id;
    });
    auto const existing = std::ranges::find_if(store.fallback_keys, [&key](PersistentFallbackKey const& current) {
        return current.user_id == key.user_id && current.device_id == key.device_id && current.key_id == key.key_id;
    });
    if (existing != store.fallback_keys.end())
    {
        existing->json = std::move(key.json);
        return true;
    }
    store.fallback_keys.push_back(std::move(key));
    return true;
}

[[nodiscard]] auto find_fallback_key(PersistentStore const& store, std::string_view user_id, std::string_view device_id,
                                     std::string_view algorithm) -> std::optional<PersistentFallbackKey>
{
    auto const prefix = std::string{algorithm} + ':';
    auto const existing = std::ranges::find_if(
        store.fallback_keys, [user_id, device_id, algorithm, &prefix](PersistentFallbackKey const& key) {
            return key.user_id == user_id && key.device_id == device_id &&
                   (algorithm.empty() || key.key_id.starts_with(prefix));
        });
    return existing == store.fallback_keys.end() ? std::nullopt : std::optional<PersistentFallbackKey>{*existing};
}

[[nodiscard]] auto store_cross_signing_key(PersistentStore& store, PersistentCrossSigningKey key) -> bool
{
    if (!key_payload_is_valid(key.json) || key.key_type.empty())
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement(
                "upsert_cross_signing_key",
                "INSERT INTO cross_signing_keys VALUES ($1, $2, $3) ON CONFLICT (user_id, key_type) DO UPDATE SET json "
                "= $3",
                {public_value(key.user_id), public_value(key.key_type), sensitive_value(key.json)})))
    {
        return false;
    }
    auto const existing =
        std::ranges::find_if(store.cross_signing_keys, [&key](PersistentCrossSigningKey const& current) {
            return current.user_id == key.user_id && current.key_type == key.key_type;
        });
    if (existing != store.cross_signing_keys.end())
    {
        existing->json = std::move(key.json);
        return true;
    }
    store.cross_signing_keys.push_back(std::move(key));
    return true;
}

[[nodiscard]] auto store_cross_signing_keys(PersistentStore& store, std::vector<PersistentCrossSigningKey> keys) -> bool
{
    auto statements = std::vector<PreparedStatement>{};
    statements.reserve(keys.size());
    for (auto const& key : keys)
    {
        if (!key_payload_is_valid(key.json) || key.key_type.empty())
        {
            return false;
        }
        statements.push_back(record_statement(
            "upsert_cross_signing_key",
            "INSERT INTO cross_signing_keys VALUES ($1, $2, $3) ON CONFLICT (user_id, key_type) DO UPDATE SET json "
            "= $3",
            {public_value(key.user_id), public_value(key.key_type), sensitive_value(key.json)}));
    }
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    for (auto& key : keys)
    {
        auto const existing =
            std::ranges::find_if(store.cross_signing_keys, [&key](PersistentCrossSigningKey const& current) {
                return current.user_id == key.user_id && current.key_type == key.key_type;
            });
        if (existing != store.cross_signing_keys.end())
        {
            existing->json = std::move(key.json);
        }
        else
        {
            store.cross_signing_keys.push_back(std::move(key));
        }
    }
    return true;
}

auto rebuild_key_signature_index(PersistentStore& store) -> void
{
    store.key_signature_target_index.clear();
    for (auto position = std::size_t{0U}; position < store.key_signatures.size(); ++position)
    {
        store.key_signature_target_index[store.key_signatures[position].target_user_id].push_back(position);
    }
    store.key_signature_indexed_rows = store.key_signatures.size();
}

[[nodiscard]] auto key_signatures_for_target(PersistentStore const& store, std::string_view target_user_id)
    -> std::vector<std::reference_wrapper<PersistentKeySignature const>>
{
    auto matches = std::vector<std::reference_wrapper<PersistentKeySignature const>>{};
    if (store.key_signature_indexed_rows == store.key_signatures.size())
    {
        auto const entry = store.key_signature_target_index.find(std::string{target_user_id});
        if (entry == store.key_signature_target_index.end())
        {
            return matches;
        }
        auto consistent = true;
        for (auto const position : entry->second)
        {
            if (position >= store.key_signatures.size() ||
                store.key_signatures[position].target_user_id != target_user_id)
            {
                consistent = false;
                break;
            }
            matches.emplace_back(store.key_signatures[position]);
        }
        if (consistent)
        {
            return matches;
        }
        matches.clear();
    }
    for (auto const& row : store.key_signatures)
    {
        if (row.target_user_id == target_user_id)
        {
            matches.emplace_back(row);
        }
    }
    return matches;
}

[[nodiscard]] auto store_key_signature(PersistentStore& store, PersistentKeySignature signature) -> bool
{
    if (!key_payload_is_valid(signature.json) || signature.target_device_id.empty())
    {
        return false;
    }
    if (!record_and_persist(
            store, record_statement("upsert_key_signature",
                                    "INSERT INTO key_signatures VALUES ($1, $2, $3, $4) ON CONFLICT (signer_user_id, "
                                    "target_user_id, target_device_id) DO UPDATE SET json = $4",
                                    {public_value(signature.signer_user_id), public_value(signature.target_user_id),
                                     public_value(signature.target_device_id), sensitive_value(signature.json)})))
    {
        return false;
    }
    // Rows pushed directly (tests) leave the index behind the vector; a stale
    // index is rebuilt below rather than patched.
    auto const index_was_current = store.key_signature_indexed_rows == store.key_signatures.size();
    auto const existing =
        std::ranges::find_if(store.key_signatures, [&signature](PersistentKeySignature const& current) {
            return current.signer_user_id == signature.signer_user_id &&
                   current.target_user_id == signature.target_user_id &&
                   current.target_device_id == signature.target_device_id;
        });
    if (existing != store.key_signatures.end())
    {
        // Updated in place: the row keeps its position, so the index stays valid.
        existing->json = std::move(signature.json);
        if (!index_was_current)
        {
            rebuild_key_signature_index(store);
        }
        return true;
    }
    auto const target_user_id = signature.target_user_id;
    store.key_signatures.push_back(std::move(signature));
    if (index_was_current)
    {
        store.key_signature_target_index[target_user_id].push_back(store.key_signatures.size() - 1U);
        store.key_signature_indexed_rows = store.key_signatures.size();
    }
    else
    {
        rebuild_key_signature_index(store);
    }
    return true;
}

[[nodiscard]] auto store_key_backup_version(PersistentStore& store, PersistentKeyBackupVersion version) -> bool
{
    if (!key_payload_is_valid(version.json) || version.version.empty())
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement(
                "upsert_key_backup_version",
                "INSERT INTO key_backup_versions VALUES ($1, $2, $3) ON CONFLICT (user_id, version) DO UPDATE SET json "
                "= $3",
                {public_value(version.user_id), public_value(version.version), sensitive_value(version.json)})))
    {
        return false;
    }
    auto const existing =
        std::ranges::find_if(store.key_backup_versions, [&version](PersistentKeyBackupVersion const& current) {
            return current.user_id == version.user_id && current.version == version.version;
        });
    if (existing != store.key_backup_versions.end())
    {
        existing->json = std::move(version.json);
        return true;
    }
    store.key_backup_versions.push_back(std::move(version));
    return true;
}

[[nodiscard]] auto create_key_backup_version(PersistentStore& store, std::string_view user_id, std::string json)
    -> std::optional<std::string>
{
    if (user_id.empty() || !key_payload_is_valid(json))
    {
        return std::nullopt;
    }
    // One past the highest number ever issued to the user, so a deleted version's number is never issued again
    // and cannot inherit what was uploaded under it (F-60, ADR-0384). The versions still held are checked too:
    // the HTTP routes only create versions here, but store_key_backup_version can still write a row with any
    // number (a restored or edited database, a direct caller), and a number must not be issued twice for it.
    auto highest = std::uint64_t{0U};
    if (auto const issued = store.key_backup_version_high_water.find(std::string{user_id});
        issued != store.key_backup_version_high_water.end())
    {
        highest = issued->second;
    }
    for (auto const& held : store.key_backup_versions)
    {
        if (held.user_id != user_id)
        {
            continue;
        }
        auto number = std::uint64_t{0U};
        auto const* const end = held.version.data() + held.version.size();
        if (auto const parsed = std::from_chars(held.version.data(), end, number);
            parsed.ec == std::errc{} && parsed.ptr == end)
        {
            highest = std::max(highest, number);
        }
    }
    if (highest == std::numeric_limits<std::uint64_t>::max())
    {
        return std::nullopt;
    }
    auto const next = std::to_string(highest + 1U);
    auto const statements = std::vector<PreparedStatement>{
        record_statement("upsert_key_backup_version_counter",
                         "INSERT INTO key_backup_version_counters (user_id, last_version) VALUES ($1, $2) ON CONFLICT "
                         "(user_id) DO UPDATE SET last_version = $2",
                         {public_value(user_id), public_value(next)}),
        record_statement("insert_key_backup_version", "INSERT INTO key_backup_versions VALUES ($1, $2, $3)",
                         {public_value(user_id), public_value(next), sensitive_value(json)})};
    if (!commit_persistent_transaction(store, statements))
    {
        return std::nullopt;
    }
    store.key_backup_version_high_water[std::string{user_id}] = highest + 1U;
    store.key_backup_versions.push_back({std::string{user_id}, next, std::move(json)});
    return next;
}

[[nodiscard]] auto delete_key_backup_version(PersistentStore& store, std::string_view user_id, std::string_view version)
    -> bool
{
    auto const existing =
        std::ranges::find_if(store.key_backup_versions, [user_id, version](PersistentKeyBackupVersion const& v) {
            return v.user_id == user_id && v.version == version;
        });
    if (existing == store.key_backup_versions.end())
    {
        return true; // Already absent — treat as idempotent success.
    }
    // The spec deletes "all key data related to the backup" with the backup: the sessions go in the same
    // transaction as the version row (the table's ON DELETE CASCADE is the second line of defence), and the
    // in-memory mirror follows only once both are durable (F-60).
    auto const statements = std::vector<PreparedStatement>{
        record_statement("delete_key_backup_version_sessions",
                         "DELETE FROM key_backup_sessions WHERE user_id = $1 AND version = $2",
                         {public_value(user_id), public_value(version)}),
        record_statement("delete_key_backup_version",
                         "DELETE FROM key_backup_versions WHERE user_id = $1 AND version = $2",
                         {public_value(user_id), public_value(version)})};
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    std::erase_if(store.key_backup_sessions, [user_id, version](PersistentKeyBackupSession const& session) {
        return session.user_id == user_id && session.version == version;
    });
    store.key_backup_versions.erase(existing);
    return true;
}

[[nodiscard]] auto store_key_backup_session(PersistentStore& store, PersistentKeyBackupSession session) -> bool
{
    if (!key_payload_is_valid(session.json) || session.version.empty() || session.room_id.empty() ||
        session.session_id.empty())
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement(
                "upsert_key_backup_session",
                "INSERT INTO key_backup_sessions VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, version, room_id, "
                "session_id) DO UPDATE SET json = $5",
                {public_value(session.user_id), public_value(session.version), public_value(session.room_id),
                 public_value(session.session_id), sensitive_value(session.json)})))
    {
        return false;
    }
    auto const existing =
        std::ranges::find_if(store.key_backup_sessions, [&session](PersistentKeyBackupSession const& current) {
            return current.user_id == session.user_id && current.version == session.version &&
                   current.room_id == session.room_id && current.session_id == session.session_id;
        });
    if (existing != store.key_backup_sessions.end())
    {
        existing->json = std::move(session.json);
        return true;
    }
    store.key_backup_sessions.push_back(std::move(session));
    return true;
}

[[nodiscard]] auto store_key_backup_sessions(PersistentStore& store, std::vector<PersistentKeyBackupSession> sessions)
    -> bool
{
    auto statements = std::vector<PreparedStatement>{};
    statements.reserve(sessions.size());
    for (auto const& session : sessions)
    {
        if (!key_payload_is_valid(session.json) || session.version.empty() || session.room_id.empty() ||
            session.session_id.empty())
        {
            return false;
        }
        statements.push_back(record_statement(
            "upsert_key_backup_session",
            "INSERT INTO key_backup_sessions VALUES ($1, $2, $3, $4, $5) ON CONFLICT (user_id, version, room_id, "
            "session_id) DO UPDATE SET json = $5",
            {public_value(session.user_id), public_value(session.version), public_value(session.room_id),
             public_value(session.session_id), sensitive_value(session.json)}));
    }
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    for (auto& session : sessions)
    {
        auto const existing =
            std::ranges::find_if(store.key_backup_sessions, [&session](PersistentKeyBackupSession const& current) {
                return current.user_id == session.user_id && current.version == session.version &&
                       current.room_id == session.room_id && current.session_id == session.session_id;
            });
        if (existing != store.key_backup_sessions.end())
        {
            existing->json = std::move(session.json);
        }
        else
        {
            store.key_backup_sessions.push_back(std::move(session));
        }
    }
    return true;
}

[[nodiscard]] auto delete_key_backup_room_sessions(PersistentStore& store, std::string_view user_id,
                                                   std::string_view version, std::string_view room_id) -> bool
{
    auto const existing = std::ranges::find_if(
        store.key_backup_sessions, [user_id, version, room_id](PersistentKeyBackupSession const& session) {
            return session.user_id == user_id && session.version == version && session.room_id == room_id;
        });
    if (existing == store.key_backup_sessions.end())
    {
        return true;
    }
    if (!record_and_persist(store,
                            record_statement("delete_key_backup_room_sessions",
                                             "DELETE FROM key_backup_sessions WHERE user_id = $1 AND version = "
                                             "$2 AND room_id = $3",
                                             {public_value(user_id), public_value(version), public_value(room_id)})))
    {
        return false;
    }
    std::erase_if(store.key_backup_sessions, [user_id, version, room_id](PersistentKeyBackupSession const& session) {
        return session.user_id == user_id && session.version == version && session.room_id == room_id;
    });
    return true;
}

[[nodiscard]] auto delete_key_backup_session(PersistentStore& store, std::string_view user_id, std::string_view version,
                                             std::string_view room_id, std::string_view session_id) -> bool
{
    auto const existing = std::ranges::find_if(
        store.key_backup_sessions, [user_id, version, room_id, session_id](PersistentKeyBackupSession const& session) {
            return session.user_id == user_id && session.version == version && session.room_id == room_id &&
                   session.session_id == session_id;
        });
    if (existing == store.key_backup_sessions.end())
    {
        return true;
    }
    if (!record_and_persist(store,
                            record_statement("delete_key_backup_session",
                                             "DELETE FROM key_backup_sessions WHERE user_id = $1 AND version = $2 AND "
                                             "room_id = $3 AND session_id = $4",
                                             {public_value(user_id), public_value(version), public_value(room_id),
                                              public_value(session_id)})))
    {
        return false;
    }
    store.key_backup_sessions.erase(existing);
    return true;
}

[[nodiscard]] auto delete_all_key_backup_sessions(PersistentStore& store, std::string_view user_id,
                                                  std::string_view version) -> bool
{
    if (version.empty())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("delete_all_key_backup_sessions",
                                             "DELETE FROM key_backup_sessions WHERE user_id = $1 AND version = $2",
                                             {public_value(user_id), public_value(version)})))
    {
        return false;
    }
    std::erase_if(store.key_backup_sessions, [user_id, version](auto const& s) {
        return s.user_id == user_id && s.version == version;
    });
    return true;
}

namespace
{

    [[nodiscard]] auto insert_local_media_statement(PersistentLocalMedia const& media) -> PreparedStatement
    {
        return record_statement("insert_media",
                                "INSERT INTO media (media_id, owner_user_id, content_type, size_bytes, "
                                "hash_algorithm, digest, quarantined, removed, legacy_endpoint_visible, "
                                "upload_name) "
                                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                                {
                                    {media.media_id,                                   false},
                                    {media.owner_user_id,                              false},
                                    {media.content_type,                               false},
                                    {std::to_string(media.size_bytes),                 false},
                                    {media.hash_algorithm,                             false},
                                    {media.digest,                                     false},
                                    {media.quarantined ? "true" : "false",             false},
                                    {media.removed ? "true" : "false",                 false},
                                    {media.legacy_endpoint_visible ? "true" : "false", false},
                                    {media.upload_name,                                false}
        });
    }

    [[nodiscard]] auto delete_pending_media_upload_statement(std::string_view media_id) -> PreparedStatement
    {
        return record_statement("delete_pending_media_upload", "DELETE FROM media_pending_uploads WHERE media_id = $1",
                                {
                                    {std::string{media_id}, false}
        });
    }

    [[nodiscard]] auto insert_pending_media_upload_statement(PersistentPendingMediaUpload const& row)
        -> PreparedStatement
    {
        return record_statement("insert_pending_media_upload",
                                "INSERT INTO media_pending_uploads (media_id, owner_user_id, created_at_ms, "
                                "expires_at_ms) VALUES ($1, $2, $3, $4)",
                                {
                                    {row.media_id,                      false},
                                    {row.owner_user_id,                 false},
                                    {std::to_string(row.created_at_ms), false},
                                    {std::to_string(row.expires_at_ms), false}
        });
    }

    [[nodiscard]] auto upsert_media_blob_statement(PersistentMediaBlob const& blob) -> PreparedStatement
    {
        return record_statement("upsert_media_blob",
                                "INSERT INTO media_blobs VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT "
                                "(storage_id) DO "
                                "UPDATE SET hash_algorithm = $2, digest = $3, size_bytes = $4, bytes = "
                                "$5, ref_count = $6",
                                {
                                    {blob.storage_id, false},
                                    {blob.hash_algorithm, false},
                                    {blob.digest, false},
                                    {std::to_string(blob.size_bytes), false},
                                    // Raw binary payload (BLOB column): marked `binary` so
                                    // PostgreSQL binds it byte-exactly, and `sensitive` so
                                    // the content never reaches a query trace or log.
                                    {blob.bytes, true, true},
                                    {std::to_string(blob.ref_count), false}
        });
    }

    [[nodiscard]] auto local_media_row_is_valid(PersistentStore const& store, PersistentLocalMedia const& media) -> bool
    {
        if (!media_hash_is_valid(media.hash_algorithm, media.digest) || media.size_bytes == 0U)
        {
            return false;
        }
        return std::ranges::none_of(store.local_media, [&media](PersistentLocalMedia const& existing) {
            return existing.media_id == media.media_id;
        });
    }

    [[nodiscard]] auto media_blob_row_is_valid(PersistentMediaBlob const& blob) noexcept -> bool
    {
        return !blob.storage_id.empty() && !blob.hash_algorithm.empty() && !blob.digest.empty();
    }

    // ADR-0119: once a blob row is durable the store mirrors only its
    // metadata; its bytes are read from the database on demand. The memory
    // backend is the exception, because its mirror is the database: there the
    // bytes are kept when written and left alone when only the reference count
    // changes.
    auto remember_media_blob(PersistentStore& store, PersistentMediaBlob const& blob, bool bytes_written) -> void
    {
        auto const keep_bytes = store.backend == PersistentStoreBackend::memory && bytes_written;
        auto existing = std::ranges::find_if(store.media_blobs, [&blob](PersistentMediaBlob const& current) {
            return current.storage_id == blob.storage_id;
        });
        if (existing == store.media_blobs.end())
        {
            store.media_blobs.push_back({blob.storage_id, blob.hash_algorithm, blob.digest, blob.size_bytes,
                                         keep_bytes ? blob.bytes : std::string{}, blob.ref_count});
            return;
        }
        existing->hash_algorithm = blob.hash_algorithm;
        existing->digest = blob.digest;
        existing->size_bytes = blob.size_bytes;
        existing->ref_count = blob.ref_count;
        if (bytes_written)
        {
            existing->bytes = keep_bytes ? blob.bytes : std::string{};
        }
    }

    [[nodiscard]] auto upsert_remote_media_statement(PersistentRemoteMedia const& media) -> PreparedStatement
    {
        return record_statement(
            "upsert_remote_media",
            "INSERT INTO remote_media (server_name, media_id, content_type, size_bytes, quarantined, "
            "local_media_id, fetched_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (server_name, media_id) "
            "DO UPDATE SET content_type = $3, size_bytes = $4, quarantined = $5, local_media_id = $6, "
            "fetched_at_ms = $7",
            {
                {media.server_name,                    false},
                {media.media_id,                       false},
                {media.content_type,                   false},
                {std::to_string(media.size_bytes),     false},
                {media.quarantined ? "true" : "false", false},
                {media.local_media_id,                 false},
                {std::to_string(media.fetched_at_ms),  false}
        });
    }

    [[nodiscard]] auto update_media_blob_ref_count_statement(PersistentMediaBlob const& blob) -> PreparedStatement
    {
        return record_statement("update_media_blob_ref_count",
                                "UPDATE media_blobs SET ref_count = $2 WHERE storage_id = $1",
                                {
                                    {blob.storage_id,                false},
                                    {std::to_string(blob.ref_count), false}
        });
    }

} // namespace

[[nodiscard]] auto store_local_media(PersistentStore& store, PersistentLocalMedia media) -> bool
{
    if (!local_media_row_is_valid(store, media) || !record_and_persist(store, insert_local_media_statement(media)))
    {
        return false;
    }
    store.local_media.push_back(std::move(media));
    return true;
}

[[nodiscard]] auto commit_local_media_upload(PersistentStore& store, PersistentLocalMedia media,
                                             PersistentMediaBlob const& blob, bool new_blob,
                                             std::string_view completes_pending_media_id) -> bool
{
    if (!local_media_row_is_valid(store, media) || !media_blob_row_is_valid(blob) || blob.ref_count == 0U ||
        (new_blob && blob.bytes.size() != blob.size_bytes))
    {
        return false;
    }
    // DB-5: the record and the blob it points at are durable together or not at
    // all. A record without its blob would survive a restart as unservable
    // media, and a blob without its record as an orphaned reference count.
    // ADR-0119: a deduplicated upload's bytes are already durable, so only its
    // reference count is written; re-binding them would copy the whole file.
    auto const blob_statement =
        new_blob ? upsert_media_blob_statement(blob) : update_media_blob_ref_count_statement(blob);
    auto statements = std::vector<PreparedStatement>{insert_local_media_statement(media), blob_statement};
    // ADR-0212: content for a reserved mxc:// URI replaces the reservation in
    // the same transaction, so a restart never sees both or neither.
    if (!completes_pending_media_id.empty())
    {
        statements.push_back(delete_pending_media_upload_statement(completes_pending_media_id));
    }
    if (!commit_persistent_transaction(store, std::move(statements)))
    {
        return false;
    }
    store.local_media.push_back(std::move(media));
    remember_media_blob(store, blob, new_blob);
    if (!completes_pending_media_id.empty())
    {
        std::erase_if(store.pending_media_uploads,
                      [completes_pending_media_id](PersistentPendingMediaUpload const& row) {
                          return row.media_id == completes_pending_media_id;
                      });
    }
    return true;
}

[[nodiscard]] auto commit_pending_media_upload(PersistentStore& store, PersistentPendingMediaUpload row,
                                               std::vector<std::string> const& expired_media_ids) -> bool
{
    if (row.media_id.empty() || row.owner_user_id.empty() || row.expires_at_ms <= row.created_at_ms ||
        std::ranges::any_of(store.pending_media_uploads,
                            [&row](PersistentPendingMediaUpload const& existing) {
                                return existing.media_id == row.media_id;
                            }) ||
        std::ranges::any_of(store.local_media, [&row](PersistentLocalMedia const& existing) {
            return existing.media_id == row.media_id;
        }))
    {
        return false;
    }
    auto statements = std::vector<PreparedStatement>{};
    statements.reserve(expired_media_ids.size() + 1U);
    for (auto const& expired : expired_media_ids)
    {
        statements.push_back(delete_pending_media_upload_statement(expired));
    }
    statements.push_back(insert_pending_media_upload_statement(row));
    if (!commit_persistent_transaction(store, std::move(statements)))
    {
        return false;
    }
    std::erase_if(store.pending_media_uploads, [&expired_media_ids](PersistentPendingMediaUpload const& existing) {
        return std::ranges::find(expired_media_ids, existing.media_id) != expired_media_ids.end();
    });
    store.pending_media_uploads.push_back(std::move(row));
    return true;
}

auto prepare_media_blob_read(PersistentStore const& store, std::string_view storage_id) -> MediaBlobRead
{
    auto read = MediaBlobRead{};
    read.backend = store.backend;
    read.storage_id = std::string{storage_id};
    read.sqlite_path = store.sqlite_path;
    read.postgresql_conninfo = store.postgresql_conninfo;
    read.postgresql_runtime_role = store.postgresql_runtime_role;
    if (store.backend == PersistentStoreBackend::memory)
    {
        auto const blob = std::ranges::find_if(store.media_blobs, [storage_id](PersistentMediaBlob const& row) {
            return row.storage_id == storage_id && row.ref_count > 0U;
        });
        if (blob != store.media_blobs.end())
        {
            read.memory_bytes = blob->bytes;
        }
    }
    return read;
}

auto read_media_blob(MediaBlobRead const& read) -> std::optional<std::string>
{
    switch (read.backend)
    {
    case PersistentStoreBackend::memory:
        return read.memory_bytes;
    case PersistentStoreBackend::sqlite:
        return detail::read_media_blob_from_sqlite(read.sqlite_path, read.storage_id);
    case PersistentStoreBackend::postgresql:
        return detail::read_media_blob_from_postgresql(read.postgresql_conninfo, read.postgresql_runtime_role,
                                                       read.storage_id);
    }
    return std::nullopt;
}

[[nodiscard]] auto update_local_media_state(PersistentStore& store, std::string_view media_id, bool quarantined,
                                            bool removed) -> bool
{
    auto const existing = std::ranges::find_if(store.local_media, [media_id](PersistentLocalMedia const& media) {
        return media.media_id == media_id;
    });
    if (existing == store.local_media.end())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("update_media_state",
                                             "UPDATE media SET quarantined = $2, removed = $3 WHERE media_id = $1",
                                             {
                                                 {std::string{media_id},          false},
                                                 {quarantined ? "true" : "false", false},
                                                 {removed ? "true" : "false",     false}
    })))
    {
        return false;
    }
    existing->quarantined = quarantined;
    existing->removed = removed;
    return true;
}

[[nodiscard]] auto commit_local_media_moderation(PersistentStore& store, std::string_view media_id, bool quarantined,
                                                 bool removed, PersistentAdminAction action, PersistentAuditEvent audit)
    -> bool
{
    auto const media = std::ranges::find_if(store.local_media, [media_id](auto const& row) {
        return row.media_id == media_id;
    });
    if (media == store.local_media.end() || media->removed || (removed && quarantined) || action.target != media_id)
    {
        return false;
    }
    auto blob = store.media_blobs.end();
    if (removed)
    {
        auto const matches = [&media](auto const& row) {
            return row.hash_algorithm == media->hash_algorithm && row.digest == media->digest &&
                   row.size_bytes == media->size_bytes && row.ref_count > 0U;
        };
        blob = std::ranges::find_if(store.media_blobs, matches);
        if (blob == store.media_blobs.end() || std::ranges::count_if(store.media_blobs, matches) != 1)
        {
            return false;
        }
    }
    audit.actor = observability::bounded_utf8(audit.actor, observability::max_audit_field_bytes);
    audit.target = observability::bounded_utf8(audit.target, observability::max_audit_field_bytes);
    audit.reason = observability::bounded_utf8(audit.reason, observability::max_audit_field_bytes);
    auto statements = std::vector<PreparedStatement>{
        record_statement("moderate_media_state", "UPDATE media SET quarantined = $2, removed = $3 WHERE media_id = $1",
                         {public_value(media_id), public_value(quarantined ? "true" : "false"),
                          public_value(removed ? "true" : "false")})};
    if (removed)
    {
        // Do not re-bind the payload. A shared blob keeps its bytes; the final
        // reference clears them in the same transaction as removal metadata.
        statements.push_back(record_statement(
            "moderate_media_blob",
            "UPDATE media_blobs SET ref_count = $2, bytes = CASE WHEN $2 = '0' THEN $3 ELSE bytes END "
            "WHERE storage_id = $1",
            {
                public_value(blob->storage_id), public_value(std::to_string(blob->ref_count - 1U)), {"", true, true}
        }));
    }
    statements.push_back(record_statement(
        "moderate_media_admin_action", "INSERT INTO admin_actions VALUES ($1, $2, $3)",
        {public_value(action.admin_user_id), public_value(action.action), public_value(action.target)}));
    statements.push_back(record_statement(
        "moderate_media_audit",
        "INSERT INTO audit_log (category, event_type, actor, target, reason, created_at_ms) VALUES "
        "($1, $2, $3, $4, $5, $6)",
        {public_value(audit.category), public_value(audit.event_type), public_value(audit.actor),
         public_value(audit.target), public_value(audit.reason), public_value(std::to_string(current_epoch_ms()))}));
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    media->quarantined = quarantined;
    media->removed = removed;
    if (removed)
    {
        --blob->ref_count;
        if (blob->ref_count == 0U)
        {
            blob->bytes.clear();
        }
    }
    store.admin_actions.push_back(std::move(action));
    remember_audit_event(store, std::move(audit));
    return true;
}

[[nodiscard]] auto store_remote_media(PersistentStore& store, PersistentRemoteMedia media) -> bool
{
    auto const duplicate = std::ranges::any_of(store.remote_media, [&media](PersistentRemoteMedia const& existing) {
        return existing.server_name == media.server_name && existing.media_id == media.media_id;
    });
    if (duplicate)
    {
        return false;
    }
    // Insert-only, as before migration 020; the columns are named so the
    // statement survives columns being added.
    if (!record_and_persist(
            store, record_statement("insert_remote_media",
                                    "INSERT INTO remote_media (server_name, media_id, content_type, size_bytes, "
                                    "quarantined, local_media_id, fetched_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                                    {
                                        {media.server_name,                    false},
                                        {media.media_id,                       false},
                                        {media.content_type,                   false},
                                        {std::to_string(media.size_bytes),     false},
                                        {media.quarantined ? "true" : "false", false},
                                        {media.local_media_id,                 false},
                                        {std::to_string(media.fetched_at_ms),  false}
    })))
    {
        return false;
    }
    store.remote_media.push_back(std::move(media));
    return true;
}

[[nodiscard]] auto commit_remote_media_admission(PersistentStore& store, PersistentLocalMedia media,
                                                 PersistentMediaBlob const& blob, bool new_blob,
                                                 PersistentRemoteMedia mapping,
                                                 std::vector<PersistentRemoteMediaRelease> const& releases,
                                                 std::vector<PersistentBlobReferenceCount> const& released_blobs)
    -> bool
{
    if (!local_media_row_is_valid(store, media) || !media_blob_row_is_valid(blob) || blob.ref_count == 0U ||
        (new_blob && blob.bytes.size() != blob.size_bytes) || mapping.server_name.empty() || mapping.media_id.empty() ||
        mapping.local_media_id != media.media_id)
    {
        return false;
    }
    // Releases first: a release of this same (server_name, media_id) deletes the
    // old cache row, which the upsert at the end then replaces.
    auto statements = std::vector<PreparedStatement>{};
    for (auto const& release : releases)
    {
        statements.push_back(record_statement("delete_released_remote_local_media",
                                              "DELETE FROM media WHERE media_id = $1",
                                              {
                                                  {release.local_media_id, false}
        }));
        statements.push_back(record_statement("delete_released_remote_media",
                                              "DELETE FROM remote_media WHERE server_name = $1 AND media_id = $2",
                                              {
                                                  {release.server_name, false},
                                                  {release.media_id,    false}
        }));
    }
    for (auto const& released : released_blobs)
    {
        statements.push_back(
            record_statement("release_remote_media_blob",
                             "UPDATE media_blobs SET ref_count = $2, bytes = CASE WHEN $2 = '0' THEN $3 ELSE bytes END "
                             "WHERE storage_id = $1",
                             {
                                 {released.storage_id, false},
                                 {std::to_string(released.ref_count), false},
                                 {std::string{}, true, true}
        }));
    }
    statements.push_back(insert_local_media_statement(media));
    statements.push_back(new_blob ? upsert_media_blob_statement(blob) : update_media_blob_ref_count_statement(blob));
    statements.push_back(upsert_remote_media_statement(mapping));
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }

    for (auto const& release : releases)
    {
        std::erase_if(store.local_media, [&release](PersistentLocalMedia const& row) {
            return row.media_id == release.local_media_id;
        });
        std::erase_if(store.remote_media, [&release](PersistentRemoteMedia const& row) {
            return row.server_name == release.server_name && row.media_id == release.media_id;
        });
    }
    for (auto const& released : released_blobs)
    {
        auto const row = std::ranges::find_if(store.media_blobs, [&released](PersistentMediaBlob const& candidate) {
            return candidate.storage_id == released.storage_id;
        });
        if (row != store.media_blobs.end())
        {
            row->ref_count = released.ref_count;
            if (released.ref_count == 0U)
            {
                row->bytes.clear();
            }
        }
    }
    store.local_media.push_back(std::move(media));
    remember_media_blob(store, blob, new_blob);
    std::erase_if(store.remote_media, [&mapping](PersistentRemoteMedia const& row) {
        return row.server_name == mapping.server_name && row.media_id == mapping.media_id;
    });
    store.remote_media.push_back(std::move(mapping));
    return true;
}

[[nodiscard]] auto store_media_blob(PersistentStore& store, PersistentMediaBlob const& blob) -> bool
{
    if (!media_blob_row_is_valid(blob) || !record_and_persist(store, upsert_media_blob_statement(blob)))
    {
        return false;
    }
    remember_media_blob(store, blob, true);
    return true;
}

[[nodiscard]] auto append_audit_event(PersistentStore& store, PersistentAuditEvent event) -> bool
{
    // AUTH-1: actor, target and reason can carry client-supplied text. Bound them
    // here, at the lowest audit-append layer, so no caller can store more than
    // `max_audit_field_bytes` of it or leave it as malformed UTF-8. Idempotent,
    // so a caller that already bounded its values is unaffected.
    event.actor = observability::bounded_utf8(event.actor, observability::max_audit_field_bytes);
    event.target = observability::bounded_utf8(event.target, observability::max_audit_field_bytes);
    event.reason = observability::bounded_utf8(event.reason, observability::max_audit_field_bytes);
    if (event.created_at_ms == 0U)
    {
        event.created_at_ms = current_epoch_ms();
    }
    if (!record_and_persist(store,
                            record_statement("append_audit",
                                             "INSERT INTO audit_log (category, event_type, actor, target, reason, "
                                             "created_at_ms) VALUES ($1, $2, $3, $4, $5, $6)",
                                             {
                                                 {event.category,                      false},
                                                 {event.event_type,                    false},
                                                 {event.actor,                         false},
                                                 {event.target,                        false},
                                                 {event.reason,                        false},
                                                 {std::to_string(event.created_at_ms), false}
    })))
    {
        return false;
    }
    remember_audit_event(store, std::move(event));
    return true;
}

auto remember_audit_event(PersistentStore& store, PersistentAuditEvent event) -> void
{
    store.audit_log.push_back(std::move(event));
    while (store.audit_log.size() > max_in_memory_audit_events)
    {
        store.audit_log.pop_front();
        ++store.audit_log_evicted;
    }
}

[[nodiscard]] auto audit_rows_older_than_exist(PersistentStore const& store, std::uint64_t cutoff_ms)
    -> std::optional<bool>
{
    if (store.backend == PersistentStoreBackend::postgresql)
    {
        return detail::audit_rows_older_than_exist_in_postgresql(store.postgresql_conninfo,
                                                                 store.postgresql_runtime_role, cutoff_ms);
    }
    if (store.backend == PersistentStoreBackend::sqlite)
    {
        return detail::audit_rows_older_than_exist_in_sqlite(store.sqlite_path, cutoff_ms);
    }
    // No database: the window is all there is.
    return std::ranges::any_of(store.audit_log, [cutoff_ms](PersistentAuditEvent const& event) {
        return event.created_at_ms != 0U && event.created_at_ms < cutoff_ms;
    });
}

[[nodiscard]] auto delete_audit_rows_older_than(PersistentStore& store, std::uint64_t cutoff_ms, std::size_t limit)
    -> bool
{
    if (limit == 0U)
    {
        return true;
    }
    // The batch is chosen inside the statement, so a delete never holds more than `limit` rows. `limit` is a
    // size_t, so writing its digits into the text carries nothing a client chose. SQLite names rows by rowid and
    // PostgreSQL by ctid: audit_log has no key of its own (ADR-0489).
    auto const postgresql = store.backend == PersistentStoreBackend::postgresql;
    auto const row_name = std::string{postgresql ? "ctid" : "rowid"};
    auto const integer = std::string{postgresql ? "BIGINT" : "INTEGER"};
    auto const stamp = "CAST(created_at_ms AS " + integer + ")";
    return record_and_persist(store, record_statement("delete_expired_audit_rows",
                                                      "DELETE FROM audit_log WHERE " + row_name + " IN (SELECT " +
                                                          row_name + " FROM audit_log WHERE " + stamp + " > 0 AND " +
                                                          stamp + " < CAST($1 AS " + integer + ") LIMIT " +
                                                          std::to_string(limit) + ")",
                                                      {public_value(std::to_string(cutoff_ms))}));
}

auto forget_audit_events_older_than(PersistentStore& store, std::uint64_t cutoff_ms) -> std::size_t
{
    // The window is oldest first, so what is old is a prefix.
    auto removed = std::size_t{0U};
    while (!store.audit_log.empty() && store.audit_log.front().created_at_ms != 0U &&
           store.audit_log.front().created_at_ms < cutoff_ms)
    {
        store.audit_log.pop_front();
        ++removed;
    }
    return removed;
}

[[nodiscard]] auto collect_unusable_credentials(PersistentStore const& store, std::chrono::system_clock::time_point now,
                                                std::chrono::system_clock::duration expired_access_grace)
    -> UnusableCredentials
{
    auto unusable = UnusableCredentials{};
    for (auto const& token : store.access_tokens)
    {
        if (token.revoked || (token.expires_at.has_value() && *token.expires_at + expired_access_grace <= now))
        {
            unusable.access_token_hashes.push_back(token.token_hash);
        }
    }
    for (auto const& token : store.refresh_tokens)
    {
        if (token.expires_at.has_value() && *token.expires_at <= now)
        {
            unusable.refresh_token_hashes.push_back(token.token_hash);
        }
    }
    return unusable;
}

[[nodiscard]] auto delete_credential_rows(PersistentStore& store, std::span<std::string const> access_token_hashes,
                                          std::span<std::string const> refresh_token_hashes) -> bool
{
    auto statements = std::vector<PreparedStatement>{};
    statements.reserve(access_token_hashes.size() + refresh_token_hashes.size());
    for (auto const& hash : access_token_hashes)
    {
        statements.push_back(record_statement("delete_unusable_access_token",
                                              "DELETE FROM access_tokens WHERE token_hash = $1",
                                              {
                                                  {hash, true}
        }));
    }
    for (auto const& hash : refresh_token_hashes)
    {
        statements.push_back(record_statement("delete_unusable_refresh_token",
                                              "DELETE FROM refresh_tokens WHERE token_hash = $1",
                                              {
                                                  {hash, true}
        }));
    }
    return commit_persistent_transaction(store, statements);
}

auto forget_credentials(PersistentStore& store, UnusableCredentials const& deleted) -> void
{
    // Housekeeping between two stored hashes of credentials that can no longer authenticate, not a check of a
    // presented token, so a hash set is fine here.
    auto const access =
        std::unordered_set<std::string>{deleted.access_token_hashes.begin(), deleted.access_token_hashes.end()};
    auto const refresh =
        std::unordered_set<std::string>{deleted.refresh_token_hashes.begin(), deleted.refresh_token_hashes.end()};
    std::erase_if(store.access_tokens, [&access](PersistentAccessToken const& token) {
        return access.contains(token.token_hash);
    });
    std::erase_if(store.refresh_tokens, [&refresh](PersistentRefreshToken const& token) {
        return refresh.contains(token.token_hash);
    });
}

[[nodiscard]] auto load_audit_events_by_type_prefix(PersistentStore const& store, std::string_view prefix,
                                                    std::size_t limit) -> std::vector<PersistentAuditEvent>
{
    limit = std::min(limit, max_audit_query_rows);
    if (limit == 0U)
    {
        return {};
    }
    if (store.backend != PersistentStoreBackend::memory)
    {
        if (auto rows = detail::load_audit_events_from_backend(store, prefix, limit); rows.has_value())
        {
            return std::move(*rows);
        }
        log_diagnostic("audit.query_failed",
                       {
                           {"prefix", std::string{prefix}, false}
        },
                       observability::LogEventSeverity::warning);
    }
    // No database backend (or it could not be read): answer from the window.
    auto rows = std::vector<PersistentAuditEvent>{};
    for (auto event = store.audit_log.rbegin(); event != store.audit_log.rend() && rows.size() < limit; ++event)
    {
        if (event->event_type.starts_with(prefix))
        {
            rows.push_back(*event);
        }
    }
    return rows;
}

[[nodiscard]] auto append_admin_action(PersistentStore& store, PersistentAdminAction action) -> bool
{
    if (!record_and_persist(
            store,
            record_statement("append_admin_action", "INSERT INTO admin_actions VALUES ($1, $2, $3)",
                             {
                                 {action.admin_user_id, false},
                                 {action.action,        false},
                                 {action.target,        false}
    })))
    {
        return false;
    }
    store.admin_actions.push_back(std::move(action));
    return true;
}

[[nodiscard]] auto store_policy_rule(PersistentStore& store, PersistentPolicyRule rule) -> bool
{
    if (rule.rule_id.empty() || rule.scope.empty() || rule.entity.empty() || rule.action.empty())
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement("upsert_policy_rule",
                             "INSERT INTO policy_rules VALUES ($1, $2, $3, $4, $5) ON CONFLICT (rule_id) DO UPDATE "
                             "SET scope = $2, entity = $3, action = $4, reason = $5",
                             {
                                 {rule.rule_id, false},
                                 {rule.scope,   false},
                                 {rule.entity,  false},
                                 {rule.action,  false},
                                 {rule.reason,  false}
    })))
    {
        return false;
    }
    auto existing = std::ranges::find_if(store.policy_rules, [&rule](PersistentPolicyRule const& current) {
        return current.rule_id == rule.rule_id;
    });
    if (existing != store.policy_rules.end())
    {
        *existing = std::move(rule);
        return true;
    }
    store.policy_rules.push_back(std::move(rule));
    return true;
}

[[nodiscard]] auto delete_policy_rule(PersistentStore& store, std::string_view rule_id) -> bool
{
    if (rule_id.empty())
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.policy_rules, [rule_id](PersistentPolicyRule const& current) {
        return current.rule_id == rule_id;
    });
    if (existing == store.policy_rules.end())
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("delete_policy_rule", "DELETE FROM policy_rules WHERE rule_id = $1",
                                                    {public_value(rule_id)})))
    {
        return false;
    }
    store.policy_rules.erase(existing);
    return true;
}

namespace
{

    // Allocates the row's sync stream position and commits it. The in-memory mirror is left to
    // the caller, which already knows whether the row exists.
    [[nodiscard]] auto persist_account_data_row(PersistentStore& store, PersistentAccountData& data) -> bool
    {
        data.stream_id = allocate_sync_stream_id(store);
        // Per-room rows go to the dedicated `room_account_data` table whose
        // primary key includes room_id. Global rows continue to use the
        // legacy `account_data` table whose PK is (user_id, event_type).
        auto const statement =
            data.room_id.empty()
                ? record_statement(
                      "upsert_account_data",
                      "INSERT INTO account_data (user_id, event_type, json, stream_id) VALUES ($1, $2, $3, $4) "
                      "ON CONFLICT (user_id, event_type) DO UPDATE SET json = $3, stream_id = $4",
                      {public_value(data.user_id), public_value(data.event_type), sensitive_value(data.content_json),
                       public_value(std::to_string(data.stream_id))})
                : record_statement(
                      "upsert_room_account_data",
                      "INSERT INTO room_account_data (user_id, room_id, event_type, stream_id, json) VALUES ($1, "
                      "$2, $3, $4, $5) ON CONFLICT (user_id, room_id, event_type) DO UPDATE SET stream_id = $4, "
                      "json = $5",
                      {public_value(data.user_id), public_value(data.room_id), public_value(data.event_type),
                       public_value(std::to_string(data.stream_id)), sensitive_value(data.content_json)});
        return record_and_persist(store, statement);
    }

} // namespace

namespace
{

    auto const no_positions = std::vector<std::size_t>{};

    [[nodiscard]] auto account_data_index_in_step(PersistentStore const& store) noexcept -> bool
    {
        return store.account_data_indexed_rows == store.account_data.size();
    }

    // Brings the index in step with `account_data`; a writer calls this first, so that it can keep it so.
    auto ensure_account_data_index(PersistentStore& store) -> void
    {
        if (!account_data_index_in_step(store))
        {
            rebuild_account_data_index(store);
        }
    }

    auto append_account_data_row(PersistentStore& store, PersistentAccountData data) -> void
    {
        auto const position = store.account_data.size();
        store.account_data_user_index[data.user_id].push_back(position);
        store.account_data.push_back(std::move(data));
        store.account_data_indexed_rows = store.account_data.size();
    }

    // The positions of `user_id`'s rows from the index, or nullptr when the index cannot be trusted for this
    // user (out of step, or a position that no longer names one of the user's rows). An empty answer is real.
    [[nodiscard]] auto indexed_account_data_positions(PersistentStore const& store, std::string_view user_id)
        -> std::vector<std::size_t> const*
    {
        if (!account_data_index_in_step(store))
        {
            return nullptr;
        }
        auto const entry = store.account_data_user_index.find(std::string{user_id});
        if (entry == store.account_data_user_index.end())
        {
            return &no_positions;
        }
        auto const names_the_user = [&](std::size_t position) {
            return position < store.account_data.size() && store.account_data[position].user_id == user_id;
        };
        return std::ranges::all_of(entry->second, names_the_user) ? &entry->second : nullptr;
    }

    [[nodiscard]] auto find_account_data_position(PersistentStore const& store, std::string_view user_id,
                                                  std::string_view room_id, std::string_view event_type)
        -> std::optional<std::size_t>
    {
        auto const matches = [&](PersistentAccountData const& row) {
            return row.user_id == user_id && row.room_id == room_id && row.event_type == event_type;
        };
        if (auto const* positions = indexed_account_data_positions(store, user_id); positions != nullptr)
        {
            store.account_data_rows_examined.add(positions->size());
            for (auto const position : *positions)
            {
                if (matches(store.account_data[position]))
                {
                    return position;
                }
            }
            return std::nullopt;
        }
        store.account_data_rows_examined.add(store.account_data.size());
        for (auto position = std::size_t{0U}; position < store.account_data.size(); ++position)
        {
            if (matches(store.account_data[position]))
            {
                return position;
            }
        }
        return std::nullopt;
    }

} // namespace

auto rebuild_account_data_index(PersistentStore& store) -> void
{
    store.account_data_user_index.clear();
    for (auto position = std::size_t{0U}; position < store.account_data.size(); ++position)
    {
        store.account_data_user_index[store.account_data[position].user_id].push_back(position);
    }
    store.account_data_indexed_rows = store.account_data.size();
}

auto for_each_user_account_data(PersistentStore const& store, std::string_view user_id,
                                std::function<void(PersistentAccountData const&)> const& visit) -> void
{
    if (auto const* positions = indexed_account_data_positions(store, user_id); positions != nullptr)
    {
        store.account_data_rows_examined.add(positions->size());
        for (auto const position : *positions)
        {
            visit(store.account_data[position]);
        }
        return;
    }
    store.account_data_rows_examined.add(store.account_data.size());
    for (auto const& row : store.account_data)
    {
        if (row.user_id == user_id)
        {
            visit(row);
        }
    }
}

[[nodiscard]] auto find_account_data_content(PersistentStore const& store, std::string_view user_id,
                                             std::string_view room_id, std::string_view event_type)
    -> std::optional<std::string>
{
    auto const position = find_account_data_position(store, user_id, room_id, event_type);
    if (!position.has_value())
    {
        return std::nullopt;
    }
    return store.account_data[*position].content_json;
}

[[nodiscard]] auto store_account_data(PersistentStore& store, PersistentAccountData data) -> bool
{
    if (data.user_id.empty() || data.event_type.empty() || data.content_json.size() > max_account_data_row_bytes)
    {
        return false;
    }
    if (!persist_account_data_row(store, data))
    {
        return false;
    }
    ensure_account_data_index(store);
    if (auto const existing = find_account_data_position(store, data.user_id, data.room_id, data.event_type);
        existing.has_value())
    {
        store.account_data[*existing] = std::move(data);
        return true;
    }
    append_account_data_row(store, std::move(data));
    return true;
}

namespace
{

    // Stores `data` unless the user already holds `max_types` other types in the row's scope
    // (global when room_id is empty, otherwise that one room). One pass over the in-memory rows
    // both counts the types and finds the row to update, because the PUT paths run under
    // runtime.mutex. A refusal writes nothing and allocates no sync stream position.
    [[nodiscard]] auto store_account_data_within_scope_cap(PersistentStore& store, PersistentAccountData data,
                                                           std::size_t max_types) -> CappedAccountDataStore
    {
        if (data.content_json.size() > max_account_data_row_bytes)
        {
            return CappedAccountDataStore::too_large;
        }
        auto held_types = std::size_t{0U};
        auto existing = std::optional<std::size_t>{};
        ensure_account_data_index(store);
        if (auto const* positions = indexed_account_data_positions(store, data.user_id); positions != nullptr)
        {
            store.account_data_rows_examined.add(positions->size());
            for (auto const index : *positions)
            {
                auto const& row = store.account_data[index];
                if (row.room_id != data.room_id)
                {
                    continue;
                }
                ++held_types;
                if (row.event_type == data.event_type)
                {
                    existing = index;
                }
            }
        }
        if (!existing.has_value() && held_types >= max_types)
        {
            return CappedAccountDataStore::over_cap;
        }
        if (!persist_account_data_row(store, data))
        {
            return CappedAccountDataStore::failed;
        }
        if (existing.has_value())
        {
            store.account_data[*existing] = std::move(data);
        }
        else
        {
            append_account_data_row(store, std::move(data));
        }
        return CappedAccountDataStore::stored;
    }

} // namespace

[[nodiscard]] auto store_global_account_data_within_cap(PersistentStore& store, PersistentAccountData data,
                                                        std::size_t max_global_types) -> CappedAccountDataStore
{
    if (data.user_id.empty() || data.event_type.empty() || !data.room_id.empty())
    {
        return CappedAccountDataStore::failed;
    }
    return store_account_data_within_scope_cap(store, std::move(data), max_global_types);
}

[[nodiscard]] auto store_room_account_data_within_cap(PersistentStore& store, PersistentAccountData data,
                                                      std::size_t max_room_types) -> CappedAccountDataStore
{
    if (data.user_id.empty() || data.event_type.empty() || data.room_id.empty())
    {
        return CappedAccountDataStore::failed;
    }
    return store_account_data_within_scope_cap(store, std::move(data), max_room_types);
}

namespace
{

    [[nodiscard]] auto same_receipt_key(PersistentReceipt const& left, PersistentReceipt const& right) noexcept -> bool
    {
        return left.room_id == right.room_id && left.receipt_type == right.receipt_type &&
               left.user_id == right.user_id && left.thread_id == right.thread_id;
    }

} // namespace

[[nodiscard]] auto store_receipt(PersistentStore& store, PersistentReceipt receipt,
                                 std::optional<PersistentReceipt> evicted) -> bool
{
    if (receipt.room_id.empty() || receipt.receipt_type.empty() || receipt.user_id.empty() || receipt.event_id.empty())
    {
        return false;
    }
    // Defence in depth (F-53): an event ID, and the thread root's event ID a receipt may be filed
    // under, are at most 255 bytes (Appendices, "Event IDs"). Callers check the shape; this keeps a
    // row from growing past what a receipt can mean, whichever path writes it.
    if (receipt.event_id.size() > events::max_id_length_bytes || receipt.thread_id.size() > events::max_id_length_bytes)
    {
        return false;
    }
    receipt.stream_id = allocate_sync_stream_id(store);
    auto statements = std::vector<PreparedStatement>{};
    if (evicted.has_value())
    {
        statements.push_back(record_statement(
            "delete_receipt",
            "DELETE FROM receipts WHERE room_id = $1 AND receipt_type = $2 AND user_id = $3 AND thread_id = $4",
            {public_value(evicted->room_id), public_value(evicted->receipt_type), public_value(evicted->user_id),
             public_value(evicted->thread_id)}));
    }
    statements.push_back(record_statement(
        "upsert_receipt",
        "INSERT INTO receipts (room_id, receipt_type, user_id, thread_id, event_id, ts, stream_id) VALUES ($1, $2, "
        "$3, $4, $5, $6, $7) ON CONFLICT (room_id, receipt_type, user_id, thread_id) DO UPDATE SET event_id = $5, "
        "ts = $6, stream_id = $7",
        {public_value(receipt.room_id), public_value(receipt.receipt_type), public_value(receipt.user_id),
         public_value(receipt.thread_id), public_value(receipt.event_id), public_value(std::to_string(receipt.ts)),
         public_value(std::to_string(receipt.stream_id))}));
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    if (evicted.has_value())
    {
        std::erase_if(store.receipts, [&evicted](PersistentReceipt const& current) {
            return same_receipt_key(current, *evicted);
        });
    }
    auto const existing = std::ranges::find_if(store.receipts, [&receipt](PersistentReceipt const& current) {
        return same_receipt_key(current, receipt);
    });
    if (existing != store.receipts.end())
    {
        *existing = std::move(receipt);
        return true;
    }
    store.receipts.push_back(std::move(receipt));
    return true;
}

[[nodiscard]] auto remove_receipt(PersistentStore& store, PersistentReceipt const& receipt) -> bool
{
    auto const existing = std::ranges::find_if(store.receipts, [&receipt](PersistentReceipt const& current) {
        return same_receipt_key(current, receipt);
    });
    if (existing == store.receipts.end())
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("delete_receipt",
                                                    "DELETE FROM receipts WHERE room_id = $1 AND receipt_type = $2 "
                                                    "AND user_id = $3 AND thread_id = $4",
                                                    {public_value(receipt.room_id), public_value(receipt.receipt_type),
                                                     public_value(receipt.user_id), public_value(receipt.thread_id)})))
    {
        return false;
    }
    store.receipts.erase(existing);
    return true;
}

namespace
{

    // The identity of one queued row: stream ids are allocated once, but the recipient is part of the key
    // because the table's primary key is (stream_id, target_user_id, target_device_id).
    struct ToDeviceRowKey final
    {
        std::uint64_t stream_id{0U};
        std::string target_user_id{};
        std::string target_device_id{};
    };

    // One row of a recipient's queue as the byte and count bounds see it.
    struct QueuedRow final
    {
        std::uint64_t stream_id{0U};
        std::uint64_t created_at_ms{0U};
        std::uint64_t bytes{0U};
    };

    // A recipient's rows, oldest first, and their total bytes. Built from the rows once per batch, so the
    // total is right whatever happened to the rows before (eviction, acknowledgement, hydration).
    struct RecipientQueue final
    {
        std::deque<QueuedRow> rows{};
        std::uint64_t bytes{0U};
    };

    // The rows one atomic to-device write adds and evicts, and the statements
    // that do it. Building a batch changes nothing in `PersistentStore`; the
    // caller commits `statements` in one transaction and only then applies the
    // batch to the in-memory mirror.
    struct ToDeviceBatch final
    {
        std::vector<PreparedStatement> statements{};
        std::vector<PersistentToDeviceMessage> added{};
        std::vector<ToDeviceRowKey> evicted{};
        // The queue of every recipient the batch names, by `recipient_key`. Empty when the store applies no
        // bound, because nothing is then evicted.
        std::unordered_map<std::string, RecipientQueue> queues{};
    };

    // `out` is the key of a recipient; the user ID's length leads so no user ID can run into the device ID.
    auto assign_recipient_key(std::string& out, std::string_view user_id, std::string_view device_id) -> void
    {
        out.assign(std::to_string(user_id.size()));
        out.push_back(':');
        out.append(user_id);
        out.append(device_id);
    }

    [[nodiscard]] auto to_device_bounds_apply(PersistentStore const& store) noexcept -> bool
    {
        return store.to_device_message_ttl_seconds > 0U || store.max_to_device_messages_per_user_device > 0U ||
               store.max_to_device_bytes_per_user_device > 0U;
    }

    [[nodiscard]] auto to_device_message_is_valid(PersistentStore const& store,
                                                  PersistentToDeviceMessage const& message) noexcept -> bool
    {
        if (message.sender_user_id.empty() || message.target_user_id.empty() || message.message_type.empty() ||
            message.content_json.empty())
        {
            return false;
        }
        // A message the recipient's queue could never hold is refused whole (F-14); the callers that take
        // content from a client or a remote server check it first, to answer precisely.
        return to_device_content_fits(store, message.content_json) &&
               (store.max_to_device_bytes_per_user_device == 0U ||
                message.content_json.size() <= store.max_to_device_bytes_per_user_device);
    }

    // Gathers the queue of every recipient `messages` names with ONE pass over the store's rows (F-13): a
    // batch of M messages costs the queue's length, not M times it. Rows of other recipients are never
    // copied or compared beyond the recipient lookup.
    auto index_to_device_recipients(PersistentStore& store, std::vector<PersistentToDeviceMessage> const& messages,
                                    ToDeviceBatch& batch) -> void
    {
        if (!to_device_bounds_apply(store))
        {
            return;
        }
        auto key = std::string{};
        for (auto const& message : messages)
        {
            assign_recipient_key(key, message.target_user_id, message.target_device_id);
            batch.queues.try_emplace(key);
        }
        for (auto const& row : store.to_device_messages)
        {
            ++store.to_device_rows_examined;
            assign_recipient_key(key, row.target_user_id, row.target_device_id);
            auto const queue = batch.queues.find(key);
            if (queue == batch.queues.end())
            {
                continue;
            }
            auto const bytes = static_cast<std::uint64_t>(row.content_json.size());
            queue->second.rows.push_back({row.stream_id, row.created_at_ms, bytes});
            queue->second.bytes += bytes;
        }
        for (auto& [recipient, queue] : batch.queues)
        {
            std::ranges::sort(queue.rows, {}, &QueuedRow::stream_id);
            store.to_device_rows_examined += queue.rows.size();
        }
    }

    // Allocates the message's stream id, works out which rows the per-recipient
    // bounds evict to make room (CSAZ-10, F-14), and appends the DELETE and INSERT
    // statements to `batch`. Rows already added or evicted by `batch` count, so
    // two messages for one recipient in a single batch are bounded together.
    // Needs `index_to_device_recipients` to have run for the batch.
    // The stream id is consumed even if the batch is never committed; ids are
    // only ever skipped, never reused.
    auto prepare_to_device_enqueue(PersistentStore& store, PersistentToDeviceMessage message, ToDeviceBatch& batch)
        -> void
    {
        message.stream_id = allocate_sync_stream_id(store);
        message.created_at_ms = current_epoch_ms();

        auto const ttl_ms = static_cast<std::uint64_t>(store.to_device_message_ttl_seconds) * 1000ULL;
        auto const now_ms = message.created_at_ms;
        auto const message_bytes = static_cast<std::uint64_t>(message.content_json.size());

        if (to_device_bounds_apply(store))
        {
            auto key = std::string{};
            assign_recipient_key(key, message.target_user_id, message.target_device_id);
            auto& queue = batch.queues[key];
            auto const evict = [&](QueuedRow const& row) {
                batch.statements.push_back(
                    record_statement("delete_to_device_message",
                                     "DELETE FROM to_device_messages WHERE stream_id = $1 AND target_user_id = $2 AND "
                                     "target_device_id = $3",
                                     {public_value(std::to_string(row.stream_id)), public_value(message.target_user_id),
                                      public_value(message.target_device_id)}));
                batch.evicted.push_back({row.stream_id, message.target_user_id, message.target_device_id});
                queue.bytes -= row.bytes;
            };
            // created_at_ms == 0 is a row written before migration 019: its age is unknown, so it is not
            // expired here, as in the drain. The count and byte bounds still apply to it.
            if (ttl_ms > 0U)
            {
                std::erase_if(queue.rows, [&](QueuedRow const& row) {
                    auto const expired =
                        row.created_at_ms > 0U && now_ms > row.created_at_ms && now_ms - row.created_at_ms >= ttl_ms;
                    if (expired)
                    {
                        evict(row);
                    }
                    return expired;
                });
            }
            // Oldest first: room is made for the incoming message by dropping the rows that have waited longest.
            while (!queue.rows.empty() && ((store.max_to_device_messages_per_user_device > 0U &&
                                            queue.rows.size() >= store.max_to_device_messages_per_user_device) ||
                                           (store.max_to_device_bytes_per_user_device > 0U &&
                                            queue.bytes + message_bytes > store.max_to_device_bytes_per_user_device)))
            {
                evict(queue.rows.front());
                queue.rows.pop_front();
            }
            queue.rows.push_back({message.stream_id, message.created_at_ms, message_bytes});
            queue.bytes += message_bytes;
        }

        batch.statements.push_back(record_statement(
            "insert_to_device_message",
            "INSERT INTO to_device_messages (stream_id, sender_user_id, target_user_id, target_device_id, "
            "message_type, content, created_at_ms) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            {public_value(std::to_string(message.stream_id)), public_value(message.sender_user_id),
             public_value(message.target_user_id), public_value(message.target_device_id),
             public_value(message.message_type), sensitive_value(message.content_json),
             public_value(std::to_string(message.created_at_ms))}));
        batch.added.push_back(std::move(message));
    }

    // Removes `victims` from the in-memory queue in one pass over the rows (F-13), looking each row's stream id up
    // in a hash rather than comparing it with every victim.
    auto erase_to_device_rows(PersistentStore& store, std::vector<ToDeviceRowKey> const& victims) -> void
    {
        if (victims.empty())
        {
            return;
        }
        auto by_stream_id = std::unordered_multimap<std::uint64_t, std::size_t>{};
        by_stream_id.reserve(victims.size());
        for (auto position = std::size_t{0U}; position < victims.size(); ++position)
        {
            by_stream_id.emplace(victims[position].stream_id, position);
        }
        std::erase_if(store.to_device_messages, [&](PersistentToDeviceMessage const& candidate) {
            ++store.to_device_rows_examined;
            auto const [first, last] = by_stream_id.equal_range(candidate.stream_id);
            return std::any_of(first, last, [&](auto const& entry) {
                auto const& victim = victims[entry.second];
                return victim.target_user_id == candidate.target_user_id &&
                       victim.target_device_id == candidate.target_device_id;
            });
        });
    }

    // Mirrors a committed batch into memory. Call only after the commit succeeded.
    auto apply_to_device_batch(PersistentStore& store, ToDeviceBatch&& batch) -> void
    {
        for (auto& message : batch.added)
        {
            store.to_device_messages.push_back(std::move(message));
        }
        erase_to_device_rows(store, batch.evicted);
    }

    [[nodiscard]] auto insert_client_txn_statement(PersistentClientTxnRecord const& record) -> PreparedStatement
    {
        return record_statement(
            "insert_client_txn_id",
            "INSERT INTO client_txn_ids (user_id, room_id, event_type, txn_id, event_id, device_id, created_at_ms) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
            {public_value(record.user_id), public_value(record.room_id), public_value(record.event_type),
             public_value(record.txn_id), public_value(record.event_id), public_value(record.device_id),
             public_value(std::to_string(record.created_at_ms))});
    }

    // The idempotency key of a record: each part length-prefixed, so no part can run into the next. The
    // device is part of it: a transaction ID is scoped to one device (F-52, ADR-0380).
    [[nodiscard]] auto client_txn_key(std::string_view user_id, std::string_view device_id, std::string_view room_id,
                                      std::string_view event_type, std::string_view txn_id) -> std::string
    {
        auto key = std::string{};
        for (auto const part : {user_id, device_id, room_id, event_type, txn_id})
        {
            key += std::to_string(part.size());
            key.push_back(':');
            key.append(part);
        }
        return key;
    }

    auto index_client_txn(PersistentStore& store, std::size_t position) -> void
    {
        auto const& record = store.client_txn_ids[position];
        store.client_txn_key_index.emplace(
            client_txn_key(record.user_id, record.device_id, record.room_id, record.event_type, record.txn_id),
            position);
        if (!record.event_id.empty())
        {
            store.client_txn_event_index.emplace(record.event_id, position);
        }
    }

    // Gives a record that carries no time the time it is made.
    auto stamp_client_txn(PersistentClientTxnRecord& record) -> void
    {
        if (record.created_at_ms == 0U)
        {
            record.created_at_ms = current_epoch_ms();
        }
    }

    // Adds a record to `client_txn_ids` and, while the indexes cover every earlier record, to them.
    auto append_client_txn(PersistentStore& store, PersistentClientTxnRecord record) -> void
    {
        auto const covered = store.client_txn_indexed_rows == store.client_txn_ids.size();
        store.client_txn_ids.push_back(std::move(record));
        if (covered)
        {
            index_client_txn(store, store.client_txn_ids.size() - 1U);
            ++store.client_txn_indexed_rows;
        }
    }

} // namespace

[[nodiscard]] auto enqueue_to_device_messages(PersistentStore& store, std::vector<PersistentToDeviceMessage> messages)
    -> bool
{
    if (!std::ranges::all_of(messages, [&store](PersistentToDeviceMessage const& message) {
            return to_device_message_is_valid(store, message);
        }))
    {
        return false;
    }
    if (messages.empty())
    {
        return true;
    }
    auto batch = ToDeviceBatch{};
    index_to_device_recipients(store, messages, batch);
    for (auto& message : messages)
    {
        prepare_to_device_enqueue(store, std::move(message), batch);
    }
    if (!commit_persistent_transaction(store, batch.statements))
    {
        return false;
    }
    apply_to_device_batch(store, std::move(batch));
    return true;
}

[[nodiscard]] auto enqueue_to_device_message(PersistentStore& store, PersistentToDeviceMessage message) -> bool
{
    auto messages = std::vector<PersistentToDeviceMessage>{};
    messages.push_back(std::move(message));
    return enqueue_to_device_messages(store, std::move(messages));
}

[[nodiscard]] auto enqueue_to_device_messages_with_client_txn(PersistentStore& store,
                                                              std::vector<PersistentToDeviceMessage> messages,
                                                              PersistentClientTxnRecord record) -> bool
{
    if (record.user_id.empty() || record.event_type.empty() || record.txn_id.empty() ||
        !std::ranges::all_of(messages, [&store](PersistentToDeviceMessage const& message) {
            return to_device_message_is_valid(store, message);
        }))
    {
        return false;
    }
    // Already recorded (a concurrent retry that got in first): the request that
    // recorded it committed its messages in the same transaction, so there is
    // nothing left to deliver.
    if (find_client_txn_event_id(store, record.user_id, record.device_id, record.room_id, record.event_type,
                                 record.txn_id)
            .has_value())
    {
        return true;
    }
    stamp_client_txn(record);

    auto batch = ToDeviceBatch{};
    index_to_device_recipients(store, messages, batch);
    for (auto& message : messages)
    {
        prepare_to_device_enqueue(store, std::move(message), batch);
    }
    batch.statements.push_back(insert_client_txn_statement(record));
    if (!commit_persistent_transaction(store, batch.statements))
    {
        return false;
    }
    apply_to_device_batch(store, std::move(batch));
    append_client_txn(store, std::move(record));
    return true;
}

[[nodiscard]] auto to_device_content_fits(PersistentStore const& store, std::string_view content_json) noexcept -> bool
{
    return store.max_to_device_message_bytes == 0U || content_json.size() <= store.max_to_device_message_bytes;
}

[[nodiscard]] auto to_device_queue_bytes(PersistentStore const& store, std::string_view user_id,
                                         std::string_view device_id) -> std::uint64_t
{
    auto bytes = std::uint64_t{0U};
    for (auto const& row : store.to_device_messages)
    {
        if (row.target_user_id == user_id && row.target_device_id == device_id)
        {
            bytes += row.content_json.size();
        }
    }
    return bytes;
}

[[nodiscard]] auto drain_to_device_messages(PersistentStore& store, std::string_view user_id,
                                            std::string_view device_id, std::uint64_t since_stream_id,
                                            std::uint64_t upper_stream_id) -> std::vector<PersistentToDeviceMessage>
{
    // Does this message address the requesting device? Empty target_device_id
    // or "*" means broadcast to all of this user's devices; otherwise it is
    // addressed to one specific device.
    auto const addressed_to_device = [&](PersistentToDeviceMessage const& message) {
        if (message.target_user_id != user_id)
        {
            return false;
        }
        return message.target_device_id.empty() || message.target_device_id == "*" ||
               message.target_device_id == device_id;
    };

    // Delete-on-acknowledgement, not delete-on-read. The upper bound is the
    // response snapshot: newer rows stay pending so next_batch cannot
    // acknowledge a room key that was never put in the /sync response.
    auto drained = std::vector<PersistentToDeviceMessage>{};
    auto to_purge = std::vector<ToDeviceRowKey>{};
    auto const ttl_ms = static_cast<std::uint64_t>(store.to_device_message_ttl_seconds) * 1000ULL;
    auto const now_ms = current_epoch_ms();
    store.to_device_rows_examined += store.to_device_messages.size();
    for (auto const& message : store.to_device_messages)
    {
        if (!addressed_to_device(message))
        {
            continue;
        }
        if (message.stream_id > upper_stream_id)
        {
            continue;
        }
        auto const expired = ttl_ms > 0U && message.created_at_ms > 0U && (now_ms > message.created_at_ms) &&
                             (now_ms - message.created_at_ms >= ttl_ms);
        auto const acknowledged = message.stream_id <= since_stream_id;
        auto const targeted_device = !message.target_device_id.empty() && message.target_device_id != "*";
        if (expired || (acknowledged && targeted_device))
        {
            // Expired rows are removed regardless of device scope; acknowledged,
            // device-targeted rows are removed as normal. Broadcast rows are
            // shared across this user's devices and are not acknowledged
            // per-device here, so they persist until TTL or a new broadcast
            // replaces them under the per-recipient cap.
            to_purge.push_back({message.stream_id, message.target_user_id, message.target_device_id});
            continue;
        }
        if (!acknowledged)
        {
            drained.push_back(message);
        }
    }
    // Callers page through the result and acknowledge up to the last row they
    // sent, so it is ascending in stream_id whatever order the store holds.
    std::ranges::stable_sort(drained, {}, &PersistentToDeviceMessage::stream_id);
    // CSAZ-10: purge TTL-expired and acknowledged rows together in one
    // transaction, so a failed durable delete leaves the in-memory mirror
    // unchanged rather than dropping rows the client has not yet acknowledged.
    if (!to_purge.empty())
    {
        auto statements = std::vector<PreparedStatement>{};
        statements.reserve(to_purge.size());
        for (auto const& message : to_purge)
        {
            statements.push_back(
                record_statement("delete_to_device_message",
                                 "DELETE FROM to_device_messages WHERE stream_id = $1 AND target_user_id = $2 AND "
                                 "target_device_id = $3",
                                 {public_value(std::to_string(message.stream_id)), public_value(message.target_user_id),
                                  public_value(message.target_device_id)}));
        }
        if (commit_persistent_transaction(store, statements))
        {
            erase_to_device_rows(store, to_purge);
        }
    }
    return drained;
}

[[nodiscard]] auto record_device_list_changes(PersistentStore& store, std::vector<PersistentDeviceListChange> changes)
    -> bool
{
    if (changes.empty())
    {
        return true;
    }
    for (auto const& change : changes)
    {
        if (change.observer_user_id.empty() || change.subject_user_id.empty())
        {
            return false;
        }
        if (change.change_type != "changed" && change.change_type != "left")
        {
            return false;
        }
    }
    // A pair named twice in one batch keeps its last entry, so the batch can
    // never insert the same (stream_id, observer, subject) key twice.
    {
        auto seen = std::set<std::pair<std::string, std::string>>{};
        auto kept = std::vector<PersistentDeviceListChange>{};
        kept.reserve(changes.size());
        for (auto index = changes.size(); index > 0U; --index)
        {
            auto& change = changes[index - 1U];
            if (seen.emplace(change.observer_user_id, change.subject_user_id).second)
            {
                kept.push_back(std::move(change));
            }
        }
        std::ranges::reverse(kept);
        changes = std::move(kept);
    }
    // The pairs the batch touches, and which of them already have a row: one
    // pass over the table rather than one scan per change.
    auto batch_pairs = std::set<std::pair<std::string_view, std::string_view>>{};
    for (auto const& change : changes)
    {
        batch_pairs.emplace(change.observer_user_id, change.subject_user_id);
    }
    auto existing_pairs = std::set<std::pair<std::string_view, std::string_view>>{};
    for (auto const& existing : store.device_list_changes)
    {
        if (batch_pairs.contains({existing.observer_user_id, existing.subject_user_id}))
        {
            existing_pairs.emplace(existing.observer_user_id, existing.subject_user_id);
        }
    }
    // One stream position for the whole batch: the primary key is
    // (stream_id, observer, subject), so rows for distinct pairs coexist.
    auto const stream_id = allocate_sync_stream_id(store);
    auto statements = std::vector<PreparedStatement>{};
    statements.reserve(changes.size() * 2U);
    for (auto& change : changes)
    {
        change.stream_id = stream_id;
        // Replace, do not accumulate: drop the pair's earlier row (if we hold
        // one) before inserting the new one, in the same transaction.
        if (existing_pairs.contains({change.observer_user_id, change.subject_user_id}))
        {
            statements.push_back(
                record_statement("delete_device_list_change",
                                 "DELETE FROM device_list_changes WHERE observer_user_id = $1 AND "
                                 "subject_user_id = $2",
                                 {public_value(change.observer_user_id), public_value(change.subject_user_id)}));
        }
        statements.push_back(
            record_statement("insert_device_list_change",
                             "INSERT INTO device_list_changes (stream_id, observer_user_id, subject_user_id, "
                             "change_type) VALUES ($1, $2, $3, $4)",
                             {public_value(std::to_string(change.stream_id)), public_value(change.observer_user_id),
                              public_value(change.subject_user_id), public_value(change.change_type)}));
    }
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    // The views above point into `changes` and `store.device_list_changes`;
    // they are done with before either is modified.
    std::erase_if(store.device_list_changes, [&](PersistentDeviceListChange const& existing) {
        return batch_pairs.contains({existing.observer_user_id, existing.subject_user_id});
    });
    store.device_list_changes.insert(store.device_list_changes.end(), std::make_move_iterator(changes.begin()),
                                     std::make_move_iterator(changes.end()));
    return true;
}

[[nodiscard]] auto record_device_list_change(PersistentStore& store, PersistentDeviceListChange change) -> bool
{
    auto batch = std::vector<PersistentDeviceListChange>{};
    batch.push_back(std::move(change));
    return record_device_list_changes(store, std::move(batch));
}

[[nodiscard]] auto upsert_presence(PersistentStore& store, PersistentPresence state) -> bool
{
    if (state.user_id.empty() || state.presence.empty())
    {
        return false;
    }
    state.stream_id = allocate_sync_stream_id(store);
    if (!record_and_persist(
            store, record_statement(
                       "upsert_presence",
                       "INSERT INTO presence_state (user_id, stream_id, presence, status_msg, last_active_ago, "
                       "currently_active) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (user_id) DO UPDATE SET "
                       "stream_id = $2, presence = $3, status_msg = $4, last_active_ago = $5, currently_active = $6",
                       {public_value(state.user_id), public_value(std::to_string(state.stream_id)),
                        public_value(state.presence), public_value(state.status_msg),
                        public_value(std::to_string(state.last_active_ago)),
                        public_value(state.currently_active ? "true" : "false")})))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.presence_states, [&state](PersistentPresence const& current) {
        return current.user_id == state.user_id;
    });
    if (existing != store.presence_states.end())
    {
        *existing = std::move(state);
        return true;
    }
    store.presence_states.push_back(std::move(state));
    return true;
}

[[nodiscard]] auto store_room_alias(PersistentStore& store, PersistentRoomAlias alias) -> bool
{
    if (alias.room_alias.empty() || alias.room_id.empty() || room_alias_exists(store, alias.room_alias) ||
        !room_exists(store, alias.room_id))
    {
        return false;
    }
    auto const statement = record_statement(
        "insert_room_alias", "INSERT INTO room_aliases (room_alias, room_id, creator_user_id) VALUES ($1, $2, $3)",
        {public_value(alias.room_alias), public_value(alias.room_id), public_value(alias.creator_user_id)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    store.room_aliases.push_back(std::move(alias));
    return true;
}

[[nodiscard]] auto find_room_alias(PersistentStore const& store, std::string_view room_alias)
    -> std::optional<PersistentRoomAlias>
{
    auto const it = std::ranges::find_if(store.room_aliases, [room_alias](PersistentRoomAlias const& alias) {
        return alias.room_alias == room_alias;
    });
    return it == store.room_aliases.end() ? std::nullopt : std::optional<PersistentRoomAlias>{*it};
}

[[nodiscard]] auto delete_room_alias(PersistentStore& store, std::string_view room_alias) -> bool
{
    auto const it = std::ranges::find_if(store.room_aliases, [room_alias](PersistentRoomAlias const& alias) {
        return alias.room_alias == room_alias;
    });
    if (it == store.room_aliases.end())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("delete_room_alias", "DELETE FROM room_aliases WHERE room_alias = $1",
                                             {public_value(std::string{room_alias})})))
    {
        return false;
    }
    store.room_aliases.erase(it);
    return true;
}

[[nodiscard]] auto reassign_room_alias(PersistentStore& store, std::string_view room_alias,
                                       std::string_view new_room_id) -> bool
{
    auto const it = std::ranges::find_if(store.room_aliases, [room_alias](PersistentRoomAlias const& alias) {
        return alias.room_alias == room_alias;
    });
    if (it == store.room_aliases.end() || !room_exists(store, std::string{new_room_id}))
    {
        return false;
    }
    if (!record_and_persist(
            store, record_statement("reassign_room_alias", "UPDATE room_aliases SET room_id = $2 WHERE room_alias = $1",
                                    {public_value(std::string{room_alias}), public_value(std::string{new_room_id})})))
    {
        return false;
    }
    it->room_id = std::string{new_room_id};
    return true;
}

[[nodiscard]] auto persist_sync_stream_watermark(PersistentStore& store, std::uint64_t watermark) -> bool
{
    return record_and_persist(
        store, record_statement("upsert_sync_stream_watermark",
                                "INSERT INTO sync_stream_watermark (singleton, watermark) VALUES (1, $1) "
                                "ON CONFLICT (singleton) DO UPDATE SET watermark = excluded.watermark",
                                {
                                    {std::to_string(watermark), false}
    }));
}

auto restore_sync_stream_id(PersistentStore& store) -> void
{
    auto observed = store.next_sync_stream_id;
    auto const consider = [&observed](std::uint64_t candidate) noexcept {
        if (candidate > observed)
        {
            observed = candidate;
        }
    };
    // account_data vector holds both global and per-room rows; both carry a
    // monotonic sync stream id and must be considered on restart.
    for (auto const& row : store.account_data)
    {
        consider(row.stream_id);
    }
    for (auto const& row : store.to_device_messages)
    {
        consider(row.stream_id);
    }
    for (auto const& row : store.device_list_changes)
    {
        consider(row.stream_id);
    }
    for (auto const& row : store.presence_states)
    {
        consider(row.stream_id);
    }
    for (auto const& row : store.receipts)
    {
        consider(row.stream_id);
    }
    store.next_sync_stream_id = observed;
    // Persist the floor so the watermark reflects the highest sync_stream_id
    // found in durable rows. This prevents fresh upgrades from starting the
    // counter at the table default ('0') and keeps restarts monotonic even if
    // no new sync-surface allocation happens immediately after startup.
    std::ignore = persist_sync_stream_watermark(store, observed);
}

[[nodiscard]] auto allocate_sync_stream_id(PersistentStore& store) -> std::uint64_t
{
    // ADR-0315: an id is never reused, because a row below a client's since token is not delivered and
    // a to-device row there is deleted as acknowledged.
    if (store.next_sync_stream_id >= max_sync_stream_id)
    {
        throw std::overflow_error{"the sync stream counter is at its ceiling"};
    }
    store.next_sync_stream_id += 1U;
    auto const new_id = store.next_sync_stream_id;
    // Persist the new high-water mark immediately so ephemeral sync surfaces
    // (typing, receipts) cannot roll the counter backward across a restart.
    std::ignore = persist_sync_stream_watermark(store, new_id);
    return new_id;
}

[[nodiscard]] auto persist_event_stream_watermark(PersistentStore& store, std::uint64_t watermark) -> bool
{
    store.event_stream_watermark = watermark;
    return record_and_persist(
        store, record_statement("upsert_event_stream_watermark",
                                "INSERT INTO event_stream_watermark (singleton, watermark) VALUES (1, $1) "
                                "ON CONFLICT (singleton) DO UPDATE SET watermark = excluded.watermark",
                                {
                                    {std::to_string(watermark), false}
    }));
}

[[nodiscard]] auto store_filter(PersistentStore& store, PersistentFilter filter) -> bool
{
    if (filter.user_id.empty() || filter.filter_id.empty() || filter.json.empty())
    {
        return false;
    }
    auto const statement =
        record_statement("upsert_filter",
                         "INSERT INTO filters (user_id, filter_id, json) VALUES ($1, $2, $3) "
                         "ON CONFLICT (user_id, filter_id) DO UPDATE SET json = $3",
                         {public_value(filter.user_id), public_value(filter.filter_id), sensitive_value(filter.json)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    // Keep the in-memory mirror in sync; replace existing entry if present.
    auto const existing = std::ranges::find_if(store.filters, [&filter](PersistentFilter const& f) {
        return f.user_id == filter.user_id && f.filter_id == filter.filter_id;
    });
    if (existing != store.filters.end())
    {
        *existing = std::move(filter);
        return true;
    }
    store.filters.push_back(std::move(filter));
    return true;
}

[[nodiscard]] auto find_filter(PersistentStore const& store, std::string_view user_id, std::string_view filter_id)
    -> std::optional<PersistentFilter>
{
    auto const it = std::ranges::find_if(store.filters, [user_id, filter_id](PersistentFilter const& f) {
        return f.user_id == user_id && f.filter_id == filter_id;
    });
    return it == store.filters.end() ? std::nullopt : std::optional<PersistentFilter>{*it};
}

[[nodiscard]] auto store_profile(PersistentStore& store, PersistentProfile profile) -> bool
{
    if (profile.user_id.empty())
    {
        return false;
    }
    auto const statement =
        record_statement("upsert_profile",
                         "INSERT INTO profiles (user_id, displayname, avatar_url, fields_json) VALUES ($1, $2, $3, $4) "
                         "ON CONFLICT (user_id) DO UPDATE SET displayname = $2, avatar_url = $3, fields_json = $4",
                         {public_value(profile.user_id), public_value(profile.displayname),
                          public_value(profile.avatar_url), public_value(profile.fields_json)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.profiles, [&profile](PersistentProfile const& p) {
        return p.user_id == profile.user_id;
    });
    if (existing != store.profiles.end())
    {
        *existing = std::move(profile);
        return true;
    }
    store.profiles.push_back(std::move(profile));
    return true;
}

[[nodiscard]] auto find_profile(PersistentStore const& store, std::string_view user_id)
    -> std::optional<PersistentProfile>
{
    auto const it = std::ranges::find_if(store.profiles, [user_id](PersistentProfile const& p) {
        return p.user_id == user_id;
    });
    return it == store.profiles.end() ? std::nullopt : std::optional<PersistentProfile>{*it};
}

[[nodiscard]] auto store_account_threepid(PersistentStore& store, PersistentThreePidBinding binding) -> bool
{
    if (binding.user_id.empty() || binding.medium.empty() || binding.address.empty())
    {
        return false;
    }
    auto const statement = record_statement(
        "upsert_account_threepid",
        "INSERT INTO account_threepids (user_id, medium, address, country, id_server, added_at_ms, "
        "validated_at_ms, bound, client_secret, sid) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) "
        "ON CONFLICT (user_id, medium, address) DO UPDATE SET country = $4, id_server = $5, "
        "added_at_ms = $6, validated_at_ms = $7, bound = $8, client_secret = $9, sid = $10",
        {public_value(binding.user_id), public_value(binding.medium), public_value(binding.address),
         public_value(binding.country.value_or("")), public_value(binding.id_server.value_or("")),
         public_value(std::to_string(binding.added_at_ms)), public_value(std::to_string(binding.validated_at_ms)),
         public_value(binding.bound ? "true" : "false"),
         // M-08: client_secret/sid are the IS-delegated unbind auth-mode-2
         // credential pair (docs/threat-model.md). They must never surface in
         // a query trace or diagnostic log, so bind them sensitive like every
         // other secret value in this file (see sensitive_value() call sites
         // above).
         sensitive_value(binding.client_secret.value_or("")), sensitive_value(binding.sid.value_or(""))});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    // Keep the in-memory mirror in sync; replace the existing entry if present.
    auto const existing =
        std::ranges::find_if(store.account_threepids, [&binding](PersistentThreePidBinding const& current) {
            return current.user_id == binding.user_id && current.medium == binding.medium &&
                   current.address == binding.address;
        });
    if (existing != store.account_threepids.end())
    {
        *existing = std::move(binding);
        return true;
    }
    store.account_threepids.push_back(std::move(binding));
    return true;
}

[[nodiscard]] auto find_account_threepid(PersistentStore const& store, std::string_view user_id,
                                         std::string_view medium, std::string_view address)
    -> std::optional<PersistentThreePidBinding>
{
    auto const it = std::ranges::find_if(store.account_threepids, [&](PersistentThreePidBinding const& current) {
        return current.user_id == user_id && current.medium == medium && current.address == address;
    });
    return it == store.account_threepids.end() ? std::nullopt : std::optional<PersistentThreePidBinding>{*it};
}

[[nodiscard]] auto delete_account_threepid(PersistentStore& store, std::string_view user_id, std::string_view medium,
                                           std::string_view address) -> bool
{
    auto const existing = std::ranges::find_if(store.account_threepids, [&](PersistentThreePidBinding const& current) {
        return current.user_id == user_id && current.medium == medium && current.address == address;
    });
    if (existing == store.account_threepids.end())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("delete_account_threepid",
                                             "DELETE FROM account_threepids WHERE user_id = $1 AND medium = $2 "
                                             "AND address = $3",
                                             {public_value(user_id), public_value(medium), public_value(address)})))
    {
        return false;
    }
    store.account_threepids.erase(existing);
    return true;
}

[[nodiscard]] auto store_pusher(PersistentStore& store, PersistentPusher pusher) -> bool
{
    if (pusher.user_id.empty() || pusher.app_id.empty() || pusher.pushkey.empty() || pusher.kind.empty())
    {
        return false;
    }
    auto const statement = record_statement(
        "upsert_pusher",
        "INSERT INTO pushers (user_id, app_id, pushkey, kind, app_display_name, device_display_name, "
        "profile_tag, lang, data_url, data_format, data_extra_json, device_id) VALUES ($1, $2, $3, $4, $5, $6, $7, "
        "$8, $9, $10, $11, $12) "
        "ON CONFLICT (user_id, app_id, pushkey) DO UPDATE SET kind = $4, app_display_name = $5, "
        "device_display_name = $6, profile_tag = $7, lang = $8, data_url = $9, data_format = $10, "
        "data_extra_json = $11, device_id = $12",
        {public_value(pusher.user_id), public_value(pusher.app_id), public_value(pusher.pushkey),
         public_value(pusher.kind), public_value(pusher.app_display_name), public_value(pusher.device_display_name),
         public_value(pusher.profile_tag), public_value(pusher.lang), public_value(pusher.data_url),
         public_value(pusher.data_format), public_value(pusher.data_extra_json), public_value(pusher.device_id)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    // Keep the in-memory mirror in sync; replace the existing entry if present.
    auto const existing = std::ranges::find_if(store.pushers, [&pusher](PersistentPusher const& current) {
        return current.user_id == pusher.user_id && current.app_id == pusher.app_id &&
               current.pushkey == pusher.pushkey;
    });
    if (existing != store.pushers.end())
    {
        *existing = std::move(pusher);
        return true;
    }
    store.pushers.push_back(std::move(pusher));
    return true;
}

[[nodiscard]] auto find_pusher(PersistentStore const& store, std::string_view user_id, std::string_view app_id,
                               std::string_view pushkey) -> std::optional<PersistentPusher>
{
    auto const it = std::ranges::find_if(store.pushers, [&](PersistentPusher const& current) {
        return current.user_id == user_id && current.app_id == app_id && current.pushkey == pushkey;
    });
    return it == store.pushers.end() ? std::nullopt : std::optional<PersistentPusher>{*it};
}

[[nodiscard]] auto delete_pusher(PersistentStore& store, std::string_view user_id, std::string_view app_id,
                                 std::string_view pushkey) -> bool
{
    auto const existing = std::ranges::find_if(store.pushers, [&](PersistentPusher const& current) {
        return current.user_id == user_id && current.app_id == app_id && current.pushkey == pushkey;
    });
    if (existing == store.pushers.end())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("delete_pusher",
                                             "DELETE FROM pushers WHERE user_id = $1 AND app_id = $2 "
                                             "AND pushkey = $3",
                                             {public_value(user_id), public_value(app_id), public_value(pushkey)})))
    {
        return false;
    }
    store.pushers.erase(existing);
    return true;
}

[[nodiscard]] auto list_pushers_for_user(PersistentStore const& store, std::string_view user_id)
    -> std::vector<PersistentPusher>
{
    auto result = std::vector<PersistentPusher>{};
    for (auto const& pusher : store.pushers)
    {
        if (pusher.user_id == user_id)
        {
            result.push_back(pusher);
        }
    }
    return result;
}

namespace
{

    [[nodiscard]] auto notification_index_in_step(PersistentStore const& store) noexcept -> bool
    {
        return store.notification_indexed_rows == store.notifications.size();
    }

    auto ensure_notification_index(PersistentStore& store) -> void
    {
        if (!notification_index_in_step(store))
        {
            rebuild_notification_index(store);
        }
    }

    // The positions of `user_id`'s rows, or nullptr when the index cannot be trusted for this user.
    [[nodiscard]] auto indexed_notification_positions(PersistentStore const& store, std::string_view user_id)
        -> std::vector<std::size_t> const*
    {
        if (!notification_index_in_step(store))
        {
            return nullptr;
        }
        auto const entry = store.notification_user_index.find(std::string{user_id});
        if (entry == store.notification_user_index.end())
        {
            return &no_positions;
        }
        auto const names_the_user = [&](std::size_t position) {
            return position < store.notifications.size() && store.notifications[position].user_id == user_id;
        };
        return std::ranges::all_of(entry->second, names_the_user) ? &entry->second : nullptr;
    }

    // Replaces the user's row for the same event, or appends. The index must be in step.
    auto upsert_notification_row(PersistentStore& store, PersistentNotification notification) -> void
    {
        auto& positions = store.notification_user_index[notification.user_id];
        for (auto const position : positions)
        {
            if (store.notifications[position].event_id == notification.event_id)
            {
                store.notifications[position] = std::move(notification);
                return;
            }
        }
        positions.push_back(store.notifications.size());
        store.notifications.push_back(std::move(notification));
        store.notification_indexed_rows = store.notifications.size();
    }

    // Removes one row by moving the last row into its place, so the cost does not grow with the table.
    auto erase_notification_row(PersistentStore& store, std::string const& user_id, std::string const& event_id) -> void
    {
        auto const entry = store.notification_user_index.find(user_id);
        if (entry == store.notification_user_index.end())
        {
            return;
        }
        auto& positions = entry->second;
        auto const found = std::ranges::find_if(positions, [&](std::size_t position) {
            return store.notifications[position].event_id == event_id;
        });
        if (found == positions.end())
        {
            return;
        }
        auto const position = *found;
        *found = positions.back();
        positions.pop_back();
        if (positions.empty())
        {
            store.notification_user_index.erase(entry);
        }
        auto const last = store.notifications.size() - 1U;
        if (position != last)
        {
            auto& moved_positions = store.notification_user_index[store.notifications[last].user_id];
            std::ranges::replace(moved_positions, last, position);
            store.notifications[position] = std::move(store.notifications[last]);
        }
        store.notifications.pop_back();
        store.notification_indexed_rows = store.notifications.size();
    }

    struct HeldNotification final
    {
        std::string event_id{};
        std::uint64_t stream_ordering{0U};
    };

} // namespace

auto rebuild_notification_index(PersistentStore& store) -> void
{
    store.notification_user_index.clear();
    for (auto position = std::size_t{0U}; position < store.notifications.size(); ++position)
    {
        store.notification_user_index[store.notifications[position].user_id].push_back(position);
    }
    store.notification_indexed_rows = store.notifications.size();
}

[[nodiscard]] auto store_notifications(PersistentStore& store, std::vector<PersistentNotification> notifications,
                                       std::size_t max_per_user) -> bool
{
    if (notifications.empty())
    {
        return true;
    }
    if (std::ranges::any_of(notifications, [](PersistentNotification const& notification) {
            return notification.user_id.empty() || notification.room_id.empty() || notification.event_id.empty();
        }))
    {
        return false;
    }
    ensure_notification_index(store);

    auto statements = std::vector<PreparedStatement>{};
    statements.reserve(notifications.size());
    // Each notified user's rows after the batch, to decide which are over the cap before anything is written.
    auto held_by_user = std::unordered_map<std::string, std::vector<HeldNotification>>{};
    auto users_in_order = std::vector<std::string>{};
    for (auto const& notification : notifications)
    {
        statements.push_back(record_statement(
            "upsert_notification",
            "INSERT INTO notifications (user_id, room_id, event_id, stream_ordering, ts, actions, profile_tag, "
            "highlight) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (user_id, event_id) DO UPDATE SET "
            "room_id = $2, stream_ordering = $4, ts = $5, actions = $6, profile_tag = $7, highlight = $8",
            {public_value(notification.user_id), public_value(notification.room_id),
             public_value(notification.event_id), public_value(std::to_string(notification.stream_ordering)),
             public_value(std::to_string(notification.ts)), public_value(notification.actions),
             public_value(notification.profile_tag), public_value(notification.highlight ? "true" : "false")}));
        auto [held, first_for_user] = held_by_user.try_emplace(notification.user_id);
        if (first_for_user)
        {
            users_in_order.push_back(notification.user_id);
            if (auto const* positions = indexed_notification_positions(store, notification.user_id);
                positions != nullptr)
            {
                store.notification_rows_examined.add(positions->size());
                for (auto const position : *positions)
                {
                    held->second.push_back(
                        {store.notifications[position].event_id, store.notifications[position].stream_ordering});
                }
            }
        }
        auto const same_event = std::ranges::find(held->second, notification.event_id, &HeldNotification::event_id);
        if (same_event != held->second.end())
        {
            same_event->stream_ordering = notification.stream_ordering;
        }
        else
        {
            held->second.push_back({notification.event_id, notification.stream_ordering});
        }
    }

    // Bound each user's history so it cannot grow without limit under sustained message volume: the oldest rows
    // beyond `max_per_user` go, in the same transaction as the rows that made them excess.
    auto victims = std::vector<std::pair<std::string, std::string>>{};
    for (auto const& user_id : users_in_order)
    {
        auto& held = held_by_user[user_id];
        if (held.size() <= max_per_user)
        {
            continue;
        }
        std::ranges::stable_sort(held, {}, &HeldNotification::stream_ordering);
        auto const excess = held.size() - max_per_user;
        for (auto index = std::size_t{0U}; index < excess; ++index)
        {
            victims.emplace_back(user_id, held[index].event_id);
            statements.push_back(record_statement("prune_notification",
                                                  "DELETE FROM notifications WHERE user_id = $1 AND event_id = $2",
                                                  {public_value(user_id), public_value(held[index].event_id)}));
        }
    }

    // One commit for the event's rows (ADR-0440). The mirror changes only after it, so a failed commit leaves the
    // in-memory rows and the database equal (CSAZ-10).
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    for (auto& notification : notifications)
    {
        upsert_notification_row(store, std::move(notification));
    }
    for (auto const& victim : victims)
    {
        erase_notification_row(store, victim.first, victim.second);
    }
    return true;
}

[[nodiscard]] auto store_notification(PersistentStore& store, PersistentNotification notification,
                                      std::size_t max_per_user) -> bool
{
    auto batch = std::vector<PersistentNotification>{};
    batch.push_back(std::move(notification));
    return store_notifications(store, std::move(batch), max_per_user);
}

[[nodiscard]] auto list_notifications_for_user(PersistentStore const& store, std::string_view user_id)
    -> std::vector<PersistentNotification>
{
    auto result = std::vector<PersistentNotification>{};
    if (auto const* positions = indexed_notification_positions(store, user_id); positions != nullptr)
    {
        store.notification_rows_examined.add(positions->size());
        result.reserve(positions->size());
        for (auto const position : *positions)
        {
            result.push_back(store.notifications[position]);
        }
        std::ranges::stable_sort(result, {}, &PersistentNotification::stream_ordering);
        return result;
    }
    store.notification_rows_examined.add(store.notifications.size());
    for (auto const& notification : store.notifications)
    {
        if (notification.user_id == user_id)
        {
            result.push_back(notification);
        }
    }
    return result;
}

[[nodiscard]] auto store_openid_token(PersistentStore& store, PersistentOpenidToken token) -> bool
{
    if (token.user_id.empty() || !token_is_hash(token.token_hash))
    {
        return false;
    }
    auto const expires_at_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(token.expires_at.time_since_epoch()).count();
    if (!record_and_persist(
            store, record_statement("insert_openid_token",
                                    "INSERT INTO openid_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)",
                                    {public_value(token.user_id), sensitive_value(token.token_hash),
                                     public_value(std::to_string(expires_at_ms))})))
    {
        return false;
    }
    store.openid_tokens.push_back(token);

    // Retention: every insert also sweeps every already-expired row (not
    // just this user's), since an OpenID token's natural lifecycle bound is
    // its own short expiry rather than a per-user row count -- unlike
    // store_notification, which caps by count because notification history
    // has no expiry of its own.
    auto const now = std::chrono::system_clock::now();
    auto stale_hashes = std::vector<std::string>{};
    for (auto const& row : store.openid_tokens)
    {
        if (row.expires_at <= now)
        {
            stale_hashes.push_back(row.token_hash);
        }
    }
    for (auto const& stale_hash : stale_hashes)
    {
        std::ignore = record_and_persist(store, record_statement("prune_openid_token",
                                                                 "DELETE FROM openid_tokens WHERE token_hash = $1",
                                                                 {sensitive_value(stale_hash)}));
        auto const stale = std::ranges::find_if(store.openid_tokens, [&](PersistentOpenidToken const& current) {
            return current.token_hash == stale_hash;
        });
        if (stale != store.openid_tokens.end())
        {
            store.openid_tokens.erase(stale);
        }
    }
    return true;
}

[[nodiscard]] auto revoke_openid_tokens_for_user(PersistentStore& store, std::string_view user_id) -> bool
{
    auto const held = [user_id](PersistentOpenidToken const& row) {
        return row.user_id == user_id;
    };
    // Rows are mirrored into memory only after they were persisted, so no held row means no stored row.
    if (!std::ranges::any_of(store.openid_tokens, held))
    {
        return true;
    }
    if (!record_and_persist(store,
                            record_statement("revoke_openid_tokens_for_user",
                                             "DELETE FROM openid_tokens WHERE user_id = $1", {public_value(user_id)})))
    {
        return false;
    }
    std::erase_if(store.openid_tokens, held);
    return true;
}

[[nodiscard]] auto store_login_token(PersistentStore& store, PersistentLoginToken token) -> bool
{
    if (token.user_id.empty() || !token_is_hash(token.token_hash))
    {
        return false;
    }
    auto const expires_at_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(token.expires_at.time_since_epoch()).count();
    if (!record_and_persist(
            store, record_statement("insert_login_token",
                                    "INSERT INTO login_tokens (user_id, token_hash, expires_at, used) VALUES ($1, "
                                    "$2, $3, $4)",
                                    {public_value(token.user_id), sensitive_value(token.token_hash),
                                     public_value(std::to_string(expires_at_ms)),
                                     public_value(token.used ? "true" : "false")})))
    {
        return false;
    }
    store.login_tokens.push_back(token);

    // Retention: mirrors store_openid_token -- every insert sweeps every
    // already-expired-or-used row (not just this user's), since a login
    // token's natural retention bound is its own ~seconds-long expiry (or
    // single use) rather than a row count.
    auto const now = std::chrono::system_clock::now();
    auto stale_hashes = std::vector<std::string>{};
    for (auto const& row : store.login_tokens)
    {
        if (row.expires_at <= now || row.used)
        {
            stale_hashes.push_back(row.token_hash);
        }
    }
    for (auto const& stale_hash : stale_hashes)
    {
        std::ignore = record_and_persist(store, record_statement("prune_login_token",
                                                                 "DELETE FROM login_tokens WHERE token_hash = $1",
                                                                 {sensitive_value(stale_hash)}));
        auto const stale = std::ranges::find_if(store.login_tokens, [&](PersistentLoginToken const& current) {
            return current.token_hash == stale_hash;
        });
        if (stale != store.login_tokens.end())
        {
            store.login_tokens.erase(stale);
        }
    }
    return true;
}

[[nodiscard]] auto consume_login_token(PersistentStore& store, std::vector<std::string> const& candidate_hashes)
    -> std::optional<std::string>
{
    auto const now = std::chrono::system_clock::now();
    auto const matched = std::ranges::find_if(store.login_tokens, [&](PersistentLoginToken const& row) {
        if (row.used || row.expires_at <= now)
        {
            return false;
        }
        return std::ranges::any_of(candidate_hashes, [&](std::string const& candidate) {
            return crypto::constant_time_equal(row.token_hash, candidate);
        });
    });
    if (matched == store.login_tokens.end())
    {
        return std::nullopt;
    }
    // Mark used in the backend first; only flip the in-memory row (and hand
    // back the user_id) if that succeeds, so a persistence failure can never
    // leave the token silently redeemable a second time from memory alone.
    if (!record_and_persist(store, record_statement("consume_login_token",
                                                    "UPDATE login_tokens SET used = $1 WHERE token_hash = $2",
                                                    {
                                                        public_value("true"),
                                                        sensitive_value(matched->token_hash),
                                                    })))
    {
        return std::nullopt;
    }
    matched->used = true;
    return matched->user_id;
}

[[nodiscard]] auto find_appservice_txn_cursor(PersistentStore const& store, std::string_view appservice_id)
    -> PersistentAppserviceTxnCursor
{
    auto const it =
        std::ranges::find_if(store.appservice_txn_cursors, [appservice_id](PersistentAppserviceTxnCursor const& row) {
            return row.appservice_id == appservice_id;
        });
    if (it == store.appservice_txn_cursors.end())
    {
        // No row yet: the spec-correct starting state is "nothing delivered,
        // next fresh id is 1" -- not an error, since a freshly registered
        // appservice has no cursor row until its first delivery attempt.
        return PersistentAppserviceTxnCursor{std::string{appservice_id}, 1U, 0U, 0U, 0U};
    }
    return *it;
}

[[nodiscard]] auto store_appservice_txn_cursor(PersistentStore& store, PersistentAppserviceTxnCursor cursor) -> bool
{
    if (cursor.appservice_id.empty())
    {
        return false;
    }
    auto const statement = record_statement(
        "upsert_appservice_txn_cursor",
        "INSERT INTO appservice_txn_cursor (appservice_id, next_txn_id, delivered_stream_ordering, pending_txn_id, "
        "pending_stream_ordering) VALUES ($1, $2, $3, $4, $5) "
        "ON CONFLICT (appservice_id) DO UPDATE SET next_txn_id = $2, delivered_stream_ordering = $3, "
        "pending_txn_id = $4, pending_stream_ordering = $5",
        {public_value(cursor.appservice_id), public_value(std::to_string(cursor.next_txn_id)),
         public_value(std::to_string(cursor.delivered_stream_ordering)),
         public_value(std::to_string(cursor.pending_txn_id)),
         public_value(std::to_string(cursor.pending_stream_ordering))});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    auto const existing =
        std::ranges::find_if(store.appservice_txn_cursors, [&cursor](PersistentAppserviceTxnCursor const& current) {
            return current.appservice_id == cursor.appservice_id;
        });
    if (existing != store.appservice_txn_cursors.end())
    {
        *existing = std::move(cursor);
        return true;
    }
    store.appservice_txn_cursors.push_back(std::move(cursor));
    return true;
}

namespace
{

    // The outbox vector is sorted by (appservice_id, stream_ordering), compared
    // numerically: the columns are TEXT, so the backends' own ORDER BY would put
    // "10" before "9".
    [[nodiscard]] auto outbox_entry_precedes(PersistentAppserviceOutboxEntry const& entry,
                                             std::string_view appservice_id, std::uint64_t stream_ordering) noexcept
        -> bool
    {
        if (entry.appservice_id != appservice_id)
        {
            return entry.appservice_id < appservice_id;
        }
        return entry.stream_ordering < stream_ordering;
    }

    [[nodiscard]] auto outbox_lower_bound(std::vector<PersistentAppserviceOutboxEntry> const& outbox,
                                          std::string_view appservice_id, std::uint64_t stream_ordering)
    {
        // std::lower_bound, not the ranges one: the key is not an entry, and the ranges version
        // also demands the comparator accept two keys.
        return std::lower_bound(
            outbox.begin(), outbox.end(), std::pair{appservice_id, stream_ordering},
            [](PersistentAppserviceOutboxEntry const& entry, std::pair<std::string_view, std::uint64_t> const& key) {
                return outbox_entry_precedes(entry, key.first, key.second);
            });
    }

} // namespace

[[nodiscard]] auto enqueue_appservice_event(PersistentStore& store, PersistentAppserviceOutboxEntry entry) -> bool
{
    if (entry.appservice_id.empty() || entry.event_id.empty())
    {
        return false;
    }
    auto const position = outbox_lower_bound(store.appservice_outbox, entry.appservice_id, entry.stream_ordering);
    if (position != store.appservice_outbox.end() && position->appservice_id == entry.appservice_id &&
        position->stream_ordering == entry.stream_ordering)
    {
        return true; // already queued: the primary key is the only dedupe
    }
    auto const statement =
        record_statement("enqueue_appservice_event",
                         "INSERT INTO appservice_outbox (appservice_id, stream_ordering, event_id) VALUES ($1, $2, $3) "
                         "ON CONFLICT (appservice_id, stream_ordering) DO NOTHING",
                         {public_value(entry.appservice_id), public_value(std::to_string(entry.stream_ordering)),
                          public_value(entry.event_id)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    store.appservice_outbox.insert(position, std::move(entry));
    return true;
}

[[nodiscard]] auto count_appservice_outbox_entries(PersistentStore const& store, std::string_view appservice_id)
    -> std::size_t
{
    // The vector is sorted by appservice_id first, so one appservice's rows are contiguous and two
    // binary searches bound them: this runs per event under runtime.mutex, so it must not scan.
    auto const first = outbox_lower_bound(store.appservice_outbox, appservice_id, 0U);
    auto const last = std::upper_bound(first, store.appservice_outbox.end(), appservice_id,
                                       [](std::string_view id, PersistentAppserviceOutboxEntry const& entry) {
                                           return id < entry.appservice_id;
                                       });
    return static_cast<std::size_t>(std::distance(first, last));
}

[[nodiscard]] auto has_appservice_outbox_entry(PersistentStore const& store, std::string_view appservice_id,
                                               std::uint64_t stream_ordering) -> bool
{
    auto const position = outbox_lower_bound(store.appservice_outbox, appservice_id, stream_ordering);
    return position != store.appservice_outbox.end() && position->appservice_id == appservice_id &&
           position->stream_ordering == stream_ordering;
}

namespace
{

    [[nodiscard]] auto same_directory_entry(PersistentAppserviceDirectoryEntry const& left,
                                            PersistentAppserviceDirectoryEntry const& right) noexcept -> bool
    {
        return left.appservice_id == right.appservice_id && left.network_id == right.network_id &&
               left.room_id == right.room_id;
    }

} // namespace

[[nodiscard]] auto set_appservice_directory_entry(PersistentStore& store, PersistentAppserviceDirectoryEntry entry,
                                                  bool listed) -> bool
{
    if (entry.appservice_id.empty() || entry.network_id.empty() || entry.room_id.empty())
    {
        return false;
    }
    auto const existing =
        std::ranges::find_if(store.appservice_directory, [&entry](PersistentAppserviceDirectoryEntry const& row) {
            return same_directory_entry(row, entry);
        });
    if (listed == (existing != store.appservice_directory.end()))
    {
        return true; // already in the requested state
    }
    auto const bound = std::vector<BoundValue>{public_value(entry.appservice_id), public_value(entry.network_id),
                                               public_value(entry.room_id)};
    auto const statement =
        listed ? record_statement("list_appservice_directory",
                                  "INSERT INTO appservice_directory (appservice_id, network_id, room_id) VALUES "
                                  "($1, $2, $3) ON CONFLICT (appservice_id, network_id, room_id) DO NOTHING",
                                  bound)
               : record_statement("unlist_appservice_directory",
                                  "DELETE FROM appservice_directory WHERE appservice_id = $1 AND network_id = $2 "
                                  "AND room_id = $3",
                                  bound);
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    if (listed)
    {
        store.appservice_directory.push_back(std::move(entry));
    }
    else
    {
        store.appservice_directory.erase(existing);
    }
    return true;
}

[[nodiscard]] auto appservice_directory_contains(PersistentStore const& store, std::string_view appservice_id,
                                                 std::string_view network_id, std::string_view room_id) -> bool
{
    return std::ranges::any_of(store.appservice_directory, [&](PersistentAppserviceDirectoryEntry const& row) {
        return row.appservice_id == appservice_id && row.network_id == network_id && row.room_id == room_id;
    });
}

[[nodiscard]] auto find_first_appservice_outbox_entry(PersistentStore const& store, std::string_view appservice_id)
    -> std::optional<PersistentAppserviceOutboxEntry>
{
    auto const position = outbox_lower_bound(store.appservice_outbox, appservice_id, 0U);
    if (position == store.appservice_outbox.end() || position->appservice_id != appservice_id)
    {
        return std::nullopt;
    }
    return *position;
}

auto sort_appservice_outbox(PersistentStore& store) -> void
{
    std::ranges::sort(store.appservice_outbox,
                      [](PersistentAppserviceOutboxEntry const& left, PersistentAppserviceOutboxEntry const& right) {
                          return outbox_entry_precedes(left, right.appservice_id, right.stream_ordering);
                      });
}

auto sort_to_device_messages(PersistentStore& store) -> void
{
    std::ranges::stable_sort(store.to_device_messages, {}, &PersistentToDeviceMessage::stream_id);
}

[[nodiscard]] auto complete_appservice_delivery(PersistentStore& store, std::string_view appservice_id,
                                                std::uint64_t delivered_stream_ordering) -> bool
{
    if (appservice_id.empty())
    {
        return false;
    }
    auto cursor = find_appservice_txn_cursor(store, appservice_id);
    cursor.pending_txn_id = 0U;
    cursor.pending_stream_ordering = 0U;
    cursor.delivered_stream_ordering = std::max(cursor.delivered_stream_ordering, delivered_stream_ordering);

    auto const statements = std::vector<PreparedStatement>{
        record_statement("upsert_appservice_txn_cursor",
                         "INSERT INTO appservice_txn_cursor (appservice_id, next_txn_id, delivered_stream_ordering, "
                         "pending_txn_id, pending_stream_ordering) VALUES ($1, $2, $3, $4, $5) "
                         "ON CONFLICT (appservice_id) DO UPDATE SET next_txn_id = $2, delivered_stream_ordering = $3, "
                         "pending_txn_id = $4, pending_stream_ordering = $5",
                         {public_value(cursor.appservice_id), public_value(std::to_string(cursor.next_txn_id)),
                          public_value(std::to_string(cursor.delivered_stream_ordering)),
                          public_value(std::to_string(cursor.pending_txn_id)),
                          public_value(std::to_string(cursor.pending_stream_ordering))}),
        record_statement(
            "complete_appservice_outbox_entry",
            "DELETE FROM appservice_outbox WHERE appservice_id = $1 AND stream_ordering = $2",
            {public_value(std::string{appservice_id}), public_value(std::to_string(delivered_stream_ordering))}),
    };
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }

    // Memory follows the commit, never precedes it.
    auto const cursor_row =
        std::ranges::find_if(store.appservice_txn_cursors, [&cursor](PersistentAppserviceTxnCursor const& current) {
            return current.appservice_id == cursor.appservice_id;
        });
    if (cursor_row != store.appservice_txn_cursors.end())
    {
        *cursor_row = cursor;
    }
    else
    {
        store.appservice_txn_cursors.push_back(cursor);
    }
    auto const position = outbox_lower_bound(store.appservice_outbox, appservice_id, delivered_stream_ordering);
    if (position != store.appservice_outbox.end() && position->appservice_id == appservice_id &&
        position->stream_ordering == delivered_stream_ordering)
    {
        store.appservice_outbox.erase(position);
    }
    return true;
}

namespace
{

    // The strings of the top-level array member `key` of a PDU's JSON; empty when the member is missing
    // or not an array. Non-string elements are skipped.
    [[nodiscard]] auto top_level_string_array(canonicaljson::Value const& pdu, std::string_view key)
        -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        auto const* object = std::get_if<canonicaljson::Object>(&pdu.storage());
        if (object == nullptr)
        {
            return result;
        }
        for (auto const& member : *object)
        {
            if (member.key != key)
            {
                continue;
            }
            auto const* array = std::get_if<canonicaljson::Array>(&member.value->storage());
            if (array == nullptr)
            {
                break;
            }
            for (auto const& element : *array)
            {
                if (auto const* text = std::get_if<std::string>(&element.storage()); text != nullptr)
                {
                    result.push_back(*text);
                }
            }
            break;
        }
        return result;
    }

    // The event IDs a retained PDU is indexed under: the ones it is missing now. A PDU that is
    // retained although it is missing nothing (its state before it could not be resolved) is
    // indexed under everything it references, so an event it names arriving still wakes it.
    [[nodiscard]] auto awaited_event_ids(PersistentStore const& store, std::string_view pdu_json)
        -> std::vector<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(pdu_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return {};
        }
        auto auth = top_level_string_array(parsed.value, "auth_events");
        auto prev = top_level_string_array(parsed.value, "prev_events");
        auto missing = find_missing_event_references(store, auth, prev);
        auto awaited = std::move(missing.auth);
        awaited.insert(awaited.end(), std::make_move_iterator(missing.prev.begin()),
                       std::make_move_iterator(missing.prev.end()));
        if (awaited.empty())
        {
            awaited = std::move(auth);
            awaited.insert(awaited.end(), std::make_move_iterator(prev.begin()), std::make_move_iterator(prev.end()));
        }
        std::ranges::sort(awaited);
        awaited.erase(std::ranges::unique(awaited).begin(), awaited.end());
        return awaited;
    }

    auto unindex_deferred_pdu(DeferredPduAwaits& awaits, std::string_view event_id) -> void
    {
        auto const row = awaits.awaited_by_row.find(std::string{event_id});
        if (row == awaits.awaited_by_row.end())
        {
            return;
        }
        for (auto const& awaited : row->second)
        {
            auto const waiting = awaits.rows_by_awaited.find(awaited);
            if (waiting == awaits.rows_by_awaited.end())
            {
                continue;
            }
            waiting->second.erase(std::string{event_id});
            if (waiting->second.empty())
            {
                awaits.rows_by_awaited.erase(waiting);
            }
        }
        awaits.awaited_by_row.erase(row);
    }

    auto index_deferred_pdu(PersistentStore& store, PersistentDeferredPdu const& row) -> void
    {
        auto& awaits = store.deferred_pdu_awaits;
        unindex_deferred_pdu(awaits, row.event_id);
        auto awaited = awaited_event_ids(store, row.pdu_json);
        for (auto const& awaited_id : awaited)
        {
            awaits.rows_by_awaited[awaited_id].insert_or_assign(row.event_id, row.room_id);
        }
        awaits.awaited_by_row.insert_or_assign(row.event_id, std::move(awaited));
    }

} // namespace

[[nodiscard]] auto find_missing_event_references(PersistentStore const& store,
                                                 std::vector<std::string> const& auth_event_ids,
                                                 std::vector<std::string> const& prev_event_ids)
    -> MissingEventReferences
{
    auto missing = MissingEventReferences{};
    for (auto const& id : auth_event_ids)
    {
        if (!store.events.contains(id))
        {
            missing.auth.push_back(id);
        }
    }
    for (auto const& id : prev_event_ids)
    {
        if (!store.events.contains(id) || !store.event_state_groups.contains(id))
        {
            missing.prev.push_back(id);
        }
    }
    return missing;
}

auto rebuild_deferred_pdu_awaits(PersistentStore& store) -> void
{
    store.deferred_pdu_awaits = DeferredPduAwaits{};
    for (auto const& row : store.deferred_pdus)
    {
        index_deferred_pdu(store, row);
    }
    store.deferred_pdu_awaits.indexed_rows = store.deferred_pdus.size();
}

[[nodiscard]] auto take_deferred_pdus_awaiting(PersistentStore& store, std::string_view room_id,
                                               std::string_view event_id) -> std::vector<std::string>
{
    if (store.deferred_pdu_awaits.indexed_rows != store.deferred_pdus.size())
    {
        rebuild_deferred_pdu_awaits(store);
    }
    auto& awaits = store.deferred_pdu_awaits;
    auto woken = std::vector<std::string>{};
    auto const waiting = awaits.rows_by_awaited.find(std::string{event_id});
    if (waiting == awaits.rows_by_awaited.end())
    {
        return woken;
    }
    for (auto it = waiting->second.begin(); it != waiting->second.end();)
    {
        if (it->second != room_id || it->first == event_id)
        {
            ++it;
            continue;
        }
        woken.push_back(it->first);
        if (auto const row = awaits.awaited_by_row.find(it->first); row != awaits.awaited_by_row.end())
        {
            std::erase(row->second, std::string{event_id});
        }
        it = waiting->second.erase(it);
    }
    if (waiting->second.empty())
    {
        awaits.rows_by_awaited.erase(waiting);
    }
    return woken;
}

[[nodiscard]] auto upsert_deferred_pdu(PersistentStore& store, PersistentDeferredPdu pdu) -> DeferredPduUpsert
{
    if (pdu.event_id.empty() || pdu.room_id.empty())
    {
        return DeferredPduUpsert::persistence_failed;
    }
    auto const existing = std::ranges::find_if(store.deferred_pdus, [&pdu](PersistentDeferredPdu const& row) {
        return row.event_id == pdu.event_id;
    });
    if (existing == store.deferred_pdus.end())
    {
        auto in_room = std::size_t{0U};
        auto json_bytes = std::size_t{0U};
        for (auto const& row : store.deferred_pdus)
        {
            if (row.room_id == pdu.room_id)
            {
                ++in_room;
            }
            json_bytes += row.pdu_json.size();
        }
        if (in_room >= max_deferred_pdus_per_room || store.deferred_pdus.size() >= max_deferred_pdus_total ||
            pdu.pdu_json.size() > max_deferred_pdu_json_bytes ||
            json_bytes > max_deferred_pdu_json_bytes - pdu.pdu_json.size())
        {
            return DeferredPduUpsert::refused_full;
        }
    }
    // An update keeps the first receive time and the PDU as first retained:
    // only the origin and the attempt count change.
    auto const statement = record_statement(
        "upsert_deferred_pdu",
        "INSERT INTO deferred_pdus (event_id, room_id, origin, pdu_json, received_at_ms, attempts) "
        "VALUES ($1, $2, $3, $4, $5, $6) "
        "ON CONFLICT (event_id) DO UPDATE SET origin = $3, attempts = $6",
        {public_value(pdu.event_id), public_value(pdu.room_id), public_value(pdu.origin), public_value(pdu.pdu_json),
         public_value(std::to_string(pdu.received_at_ms)), public_value(std::to_string(pdu.attempts))});
    if (!record_and_persist(store, statement))
    {
        return DeferredPduUpsert::persistence_failed;
    }
    // Index the row by what it is missing now (an update re-derives it: some of what it waited for may
    // have arrived). If a caller left the index behind the rows, rebuild all of it instead.
    auto const index_was_current = store.deferred_pdu_awaits.indexed_rows == store.deferred_pdus.size();
    if (existing != store.deferred_pdus.end())
    {
        existing->origin = std::move(pdu.origin);
        existing->attempts = pdu.attempts;
        if (index_was_current)
        {
            index_deferred_pdu(store, *existing);
        }
        else
        {
            rebuild_deferred_pdu_awaits(store);
        }
        return DeferredPduUpsert::updated;
    }
    store.deferred_pdus.push_back(std::move(pdu));
    if (index_was_current)
    {
        index_deferred_pdu(store, store.deferred_pdus.back());
        store.deferred_pdu_awaits.indexed_rows = store.deferred_pdus.size();
    }
    else
    {
        rebuild_deferred_pdu_awaits(store);
    }
    return DeferredPduUpsert::inserted;
}

[[nodiscard]] auto remove_deferred_pdu(PersistentStore& store, std::string_view event_id) -> bool
{
    auto const existing = std::ranges::find_if(store.deferred_pdus, [event_id](PersistentDeferredPdu const& row) {
        return row.event_id == event_id;
    });
    if (existing == store.deferred_pdus.end())
    {
        return false;
    }
    if (!record_and_persist(store,
                            record_statement("delete_deferred_pdu", "DELETE FROM deferred_pdus WHERE event_id = $1",
                                             {public_value(event_id)})))
    {
        return false;
    }
    auto const index_was_current = store.deferred_pdu_awaits.indexed_rows == store.deferred_pdus.size();
    unindex_deferred_pdu(store.deferred_pdu_awaits, event_id);
    store.deferred_pdus.erase(existing);
    if (index_was_current)
    {
        store.deferred_pdu_awaits.indexed_rows = store.deferred_pdus.size();
    }
    return true;
}

[[nodiscard]] auto list_deferred_pdus(PersistentStore const& store) -> std::vector<PersistentDeferredPdu>
{
    return store.deferred_pdus;
}

[[nodiscard]] auto deferred_pdus_for_room(PersistentStore const& store, std::string_view room_id)
    -> std::vector<PersistentDeferredPdu>
{
    auto rows = std::vector<PersistentDeferredPdu>{};
    for (auto const& row : store.deferred_pdus)
    {
        if (row.room_id == room_id)
        {
            rows.push_back(row);
        }
    }
    return rows;
}

[[nodiscard]] auto update_profile_displayname(PersistentStore& store, std::string_view user_id,
                                              std::string_view displayname) -> bool
{
    auto const it = std::ranges::find_if(store.profiles, [user_id](PersistentProfile const& p) {
        return p.user_id == user_id;
    });
    if (it == store.profiles.end())
    {
        return false;
    }
    auto const statement =
        record_statement("update_profile_displayname", "UPDATE profiles SET displayname = $2 WHERE user_id = $1",
                         {public_value(std::string{user_id}), public_value(std::string{displayname})});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    it->displayname = std::string{displayname};
    return true;
}

[[nodiscard]] auto update_profile_fields(PersistentStore& store, std::string_view user_id, std::string_view fields_json)
    -> bool
{
    auto const it = std::ranges::find_if(store.profiles, [user_id](PersistentProfile const& p) {
        return p.user_id == user_id;
    });
    if (it == store.profiles.end())
    {
        return false;
    }
    auto const statement =
        record_statement("update_profile_fields", "UPDATE profiles SET fields_json = $2 WHERE user_id = $1",
                         {public_value(std::string{user_id}), public_value(std::string{fields_json})});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    it->fields_json = std::string{fields_json};
    return true;
}

[[nodiscard]] auto update_profile_avatar_url(PersistentStore& store, std::string_view user_id,
                                             std::string_view avatar_url) -> bool
{
    auto const it = std::ranges::find_if(store.profiles, [user_id](PersistentProfile const& p) {
        return p.user_id == user_id;
    });
    if (it == store.profiles.end())
    {
        return false;
    }
    auto const statement =
        record_statement("update_profile_avatar_url", "UPDATE profiles SET avatar_url = $2 WHERE user_id = $1",
                         {public_value(std::string{user_id}), public_value(std::string{avatar_url})});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    it->avatar_url = std::string{avatar_url};
    return true;
}

[[nodiscard]] auto find_client_txn_event_id(PersistentStore const& store, std::string_view user_id,
                                            std::string_view device_id, std::string_view room_id,
                                            std::string_view event_type, std::string_view txn_id)
    -> std::optional<std::string>
{
    auto const matches = [&](PersistentClientTxnRecord const& r) {
        return r.user_id == user_id && r.device_id == device_id && r.room_id == room_id && r.event_type == event_type &&
               r.txn_id == txn_id;
    };
    if (store.client_txn_indexed_rows == store.client_txn_ids.size())
    {
        auto const entry =
            store.client_txn_key_index.find(client_txn_key(user_id, device_id, room_id, event_type, txn_id));
        if (entry == store.client_txn_key_index.end())
        {
            return std::nullopt;
        }
        if (entry->second < store.client_txn_ids.size() && matches(store.client_txn_ids[entry->second]))
        {
            return store.client_txn_ids[entry->second].event_id;
        }
        // An index that disagrees with its records is not trusted: scan.
    }
    auto const it = std::ranges::find_if(store.client_txn_ids, matches);
    if (it == store.client_txn_ids.end())
    {
        return std::nullopt;
    }
    return it->event_id;
}

[[nodiscard]] auto prune_to_device_client_txns(PersistentStore& store, std::uint64_t cutoff_ms) -> std::size_t
{
    auto const expired = [cutoff_ms](PersistentClientTxnRecord const& record) {
        return record.room_id.empty() && record.created_at_ms < cutoff_ms;
    };
    if (!std::ranges::any_of(store.client_txn_ids, expired))
    {
        return 0U;
    }
    // The column is text, so the comparison is numeric on both sides. The database goes first: a failed write
    // leaves memory as it was, and the next sweep tries again.
    if (!record_and_persist(store, record_statement("delete_expired_to_device_client_txns",
                                                    "DELETE FROM client_txn_ids WHERE room_id = '' AND "
                                                    "CAST(created_at_ms AS BIGINT) < CAST($1 AS BIGINT)",
                                                    {public_value(std::to_string(cutoff_ms))})))
    {
        return 0U;
    }
    auto const removed = std::erase_if(store.client_txn_ids, expired);
    rebuild_client_txn_index(store);
    return removed;
}

auto rebuild_client_txn_index(PersistentStore& store) -> void
{
    store.client_txn_event_index.clear();
    store.client_txn_key_index.clear();
    store.client_txn_key_index.reserve(store.client_txn_ids.size());
    store.client_txn_event_index.reserve(store.client_txn_ids.size());
    for (auto position = std::size_t{0U}; position < store.client_txn_ids.size(); ++position)
    {
        index_client_txn(store, position);
    }
    store.client_txn_indexed_rows = store.client_txn_ids.size();
}

[[nodiscard]] auto find_client_txn_by_event_id(PersistentStore const& store, std::string_view event_id)
    -> PersistentClientTxnRecord const*
{
    if (event_id.empty())
    {
        return nullptr;
    }
    if (store.client_txn_indexed_rows == store.client_txn_ids.size())
    {
        auto const entry = store.client_txn_event_index.find(std::string{event_id});
        if (entry == store.client_txn_event_index.end())
        {
            return nullptr;
        }
        if (entry->second < store.client_txn_ids.size() && store.client_txn_ids[entry->second].event_id == event_id)
        {
            return &store.client_txn_ids[entry->second];
        }
        // An index that disagrees with its records is not trusted: scan.
    }
    auto const it = std::ranges::find_if(store.client_txn_ids, [&](PersistentClientTxnRecord const& record) {
        return record.event_id == event_id;
    });
    return it == store.client_txn_ids.end() ? nullptr : &*it;
}

[[nodiscard]] auto store_client_txn(PersistentStore& store, PersistentClientTxnRecord record) -> bool
{
    if (record.user_id.empty() || record.event_type.empty() || record.txn_id.empty())
    {
        return false;
    }
    // If already recorded (concurrent retry), the original wins — do not overwrite.
    if (find_client_txn_event_id(store, record.user_id, record.device_id, record.room_id, record.event_type,
                                 record.txn_id)
            .has_value())
    {
        return true;
    }
    stamp_client_txn(record);
    if (!record_and_persist(store, insert_client_txn_statement(record)))
    {
        return false;
    }
    append_client_txn(store, std::move(record));
    return true;
}

[[nodiscard]] auto committed_transaction_count(PersistentStore const& store) -> std::uint64_t
{
    auto const lk = std::lock_guard{*store.statement_capture_mutex};
    return store.committed_transactions;
}

auto enable_statement_capture(PersistentStore& store, std::size_t capacity) -> void
{
    auto const lk = std::lock_guard{*store.statement_capture_mutex};
    store.statement_capture_capacity = std::min(capacity, max_statement_capture_capacity);
    while (store.captured_statements.size() > store.statement_capture_capacity)
    {
        store.captured_statements.pop_front();
    }
}

auto force_next_persist_failures(PersistentStore& store, std::size_t count) -> void
{
    store.force_next_persist_failures = count;
}

auto force_persist_failure_for_statement(PersistentStore& store, std::string_view statement_name) -> void
{
    store.force_failure_statement_names.emplace(std::string{statement_name});
}

[[nodiscard]] auto sensitive_values_are_redacted(PersistentStore const& store) noexcept -> bool
{
    auto const lk = std::lock_guard{*store.statement_capture_mutex};
    if (store.statement_capture_capacity == 0U)
    {
        return false;
    }
    for (auto const& statement : store.captured_statements)
    {
        for (auto const& value : statement.parameters)
        {
            if ((value.value.find("token") != std::string::npos || value.value.find("secret") != std::string::npos) &&
                !value.sensitive)
            {
                return false;
            }
        }
    }
    return true;
}

auto repair_missing_state_entries(PersistentStore& store) -> std::size_t
{
    // Older code in ingest_send_join_state and the auth-chain loop detected state
    // events by !parsed.event.state_key.empty(). Events with state_key="" (such as
    // m.room.create, m.room.join_rules, m.room.power_levels) were stored in
    // store.events but never registered in store.state. This causes
    // build_pdu_auth_event_map to find no create event, so auth step 2 fails for
    // every subsequent federated PDU in rooms joined with the old code.
    //
    // This function scans all events, identifies any that are state events (JSON
    // has a "state_key" field) but lack a store.state entry, and creates those
    // entries. For each (room_id, event_type, state_key) tuple with no entry the
    // highest-stream-ordering event is chosen as the current state.
    struct StateTuple
    {
        std::string room_id;
        std::string event_type;
        std::string state_key;
        [[nodiscard]] auto operator==(StateTuple const& other) const noexcept -> bool
        {
            return room_id == other.room_id && event_type == other.event_type && state_key == other.state_key;
        }
    };

    auto candidates = std::vector<std::pair<StateTuple, PersistentEvent const*>>{};

    for (auto const& event : store.events)
    {
        // FED-1 (ADR-0083): only an accepted event can be current state. An
        // outlier (a send_join auth-chain event, a backfilled event) or a
        // rejected or soft-failed event is stored without a state row on
        // purpose; this repair must not promote it on the next restart. The
        // legacy rows this repair exists for predate the status column and
        // read back as its default, "accepted".
        if (event.status != "accepted")
        {
            continue;
        }
        auto const json_state_key = top_level_json_string_field(event.json, "state_key");
        if (!json_state_key.has_value())
        {
            continue; // state_key field absent — not a state event
        }
        auto const json_event_type = top_level_json_string_field(event.json, "type");
        if (!json_event_type.has_value() || json_event_type->empty())
        {
            continue;
        }

        auto const tuple = StateTuple{event.room_id, *json_event_type, *json_state_key};

        // Skip tuples that already have a state entry.
        if (std::ranges::any_of(store.state, [&tuple](PersistentStateEvent const& s) {
                return s.room_id == tuple.room_id && s.event_type == tuple.event_type && s.state_key == tuple.state_key;
            }))
        {
            continue;
        }

        // Track the highest-stream-ordering event for each unrepaired tuple.
        auto it = std::ranges::find_if(candidates, [&tuple](auto const& pair) {
            return pair.first == tuple;
        });
        if (it == candidates.end())
        {
            candidates.emplace_back(tuple, &event);
        }
        else if (event.stream_ordering > it->second->stream_ordering)
        {
            it->second = &event;
        }
    }

    auto repaired = std::size_t{0U};
    for (auto const& [tuple, event] : candidates)
    {
        if (store_state(store, {tuple.room_id, tuple.event_type, tuple.state_key, event->event_id}))
        {
            ++repaired;
        }
    }
    return repaired;
}

} // namespace merovingian::database
