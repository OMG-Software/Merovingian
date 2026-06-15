// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <optional>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::database
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("persistent_store", event, std::move(fields)));
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
        return token_hash.starts_with("token-hash:v2:") || token_hash.starts_with("token-hash:v3:");
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

    [[nodiscard]] auto state_matches_persisted_event(PersistentStore const& store, PersistentStateEvent const& state)
        -> bool
    {
        auto const iterator = std::ranges::find_if(store.events, [&state](PersistentEvent const& event) {
            auto const event_type = top_level_json_string_field(event.json, "type");
            auto const state_key = top_level_json_string_field(event.json, "state_key");
            return event.event_id == state.event_id && event.room_id == state.room_id &&
                   event_type == state.event_type && state_key == state.state_key;
        });
        return iterator != store.events.end();
    }

    [[nodiscard]] auto state_matches_event(PersistentEvent const& event, PersistentStateEvent const& state) -> bool
    {
        auto const event_type = top_level_json_string_field(event.json, "type");
        auto const state_key = top_level_json_string_field(event.json, "state_key");
        return event.event_id == state.event_id && event.room_id == state.room_id && event_type == state.event_type &&
               state_key == state.state_key;
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
        return std::ranges::any_of(store.events, [event_id](PersistentEvent const& existing) {
            return existing.event_id == event_id;
        });
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
            return existing.token_hash == token_hash;
        });
    }

    [[nodiscard]] auto refresh_token_exists(PersistentStore const& store, std::string_view token_hash) -> bool
    {
        return std::ranges::any_of(store.refresh_tokens, [token_hash](PersistentRefreshToken const& existing) {
            return existing.token_hash == token_hash;
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
    store.prepared_statements.insert(store.prepared_statements.end(), statements.begin(), statements.end());
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
    if (!record_and_persist(store, record_statement("insert_user", "INSERT INTO users VALUES ($1, $2, $3, $4, $5)",
                                                    {
                                                        {user.user_id,                      false},
                                                        {user.password_hash,                true },
                                                        {user.locked ? "true" : "false",    false},
                                                        {user.suspended ? "true" : "false", false},
                                                        {user.admin ? "true" : "false",     false}
    })))
    {
        return false;
    }
    store.users.push_back(std::move(user));
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
    if (!record_and_persist(store,
                            record_statement("insert_access_token", "INSERT INTO access_tokens VALUES ($1, $2, $3, $4)",
                                             {
                                                 {token.user_id,                    false},
                                                 {token.device_id,                  false},
                                                 {token.token_hash,                 true },
                                                 {token.revoked ? "true" : "false", false}
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
                                                    "INSERT INTO refresh_tokens VALUES ($1, $2, $3, $4)",
                                                    {
                                                        {token.token_hash,                 true },
                                                        {token.user_id,                    false},
                                                        {token.device_id,                  false},
                                                        {token.revoked ? "true" : "false", false}
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
    statements.push_back(record_statement("insert_access_token", "INSERT INTO access_tokens VALUES ($1, $2, $3, $4)",
                                          {
                                              {token.user_id,                    false},
                                              {token.device_id,                  false},
                                              {token.token_hash,                 true },
                                              {token.revoked ? "true" : "false", false}
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
        if (token.token_hash == token_hash && !token.revoked)
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
        if (token.token_hash == token_hash && !token.revoked)
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
    if (!record_and_persist(store, record_statement("delete_device",
                                                    "DELETE FROM devices WHERE user_id = $1 AND device_id = $2",
                                                    {public_value(user_id), public_value(device_id)})))
    {
        return false;
    }
    store.devices.erase(existing);
    return true;
}

[[nodiscard]] auto store_server_signing_key(PersistentStore& store, PersistentServerSigningKey key) -> bool
{
    if (key.server_name.empty() || key.key_id.empty() || key.public_key.empty() || key.valid_until_ts == 0U)
    {
        return false;
    }
    if (!record_and_persist(
            store, record_statement(
                       "upsert_server_signing_key",
                       "INSERT INTO server_signing_keys VALUES ($1, $2, $3, $4, $5) ON CONFLICT (server_name, key_id) "
                       "DO UPDATE SET public_key = $3, valid_until_ts = $4, "
                       "secret_key = CASE WHEN $5 = '' THEN server_signing_keys.secret_key ELSE $5 END",
                       {public_value(key.server_name), public_value(key.key_id), public_value(key.public_key),
                        public_value(std::to_string(key.valid_until_ts)), public_value(key.secret_key)})))
    {
        return false;
    }
    auto const existing =
        std::ranges::find_if(store.server_signing_keys, [&key](PersistentServerSigningKey const& row) {
            return row.server_name == key.server_name && row.key_id == key.key_id;
        });
    if (existing != store.server_signing_keys.end())
    {
        existing->public_key = std::move(key.public_key);
        existing->valid_until_ts = key.valid_until_ts;
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
    auto const existing =
        std::ranges::find_if(store.server_signing_keys, [server_name, key_id](PersistentServerSigningKey const& key) {
            return key.server_name == server_name && key.key_id == key_id;
        });
    return existing == store.server_signing_keys.end() ? std::nullopt
                                                       : std::optional<PersistentServerSigningKey>{*existing};
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

[[nodiscard]] auto store_federation_transaction(PersistentStore& store, PersistentFederationTransaction transaction)
    -> bool
{
    if (!federation_transaction_is_valid(transaction))
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement(
                "upsert_federation_transaction",
                "INSERT INTO federation_transactions (transaction_id, server_name, json, method, target, origin, "
                "origin_server_ts, body, retry_count, next_retry_ts) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, "
                "$10) ON CONFLICT (transaction_id) DO UPDATE SET server_name = $2, json = $3, method = $4, target = "
                "$5, origin = $6, origin_server_ts = $7, body = $8, retry_count = $9, next_retry_ts = $10",
                {public_value(transaction.transaction_id), public_value(transaction.server_name),
                 sensitive_value(transaction.body), public_value(transaction.method), public_value(transaction.target),
                 public_value(transaction.origin), public_value(transaction.origin_server_ts),
                 sensitive_value(transaction.body), public_value(std::to_string(transaction.retry_count)),
                 public_value(std::to_string(transaction.next_retry_ts))})))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.federation_transactions,
                                               [&transaction](PersistentFederationTransaction const& current) {
                                                   return current.transaction_id == transaction.transaction_id;
                                               });
    if (existing != store.federation_transactions.end())
    {
        *existing = std::move(transaction);
        return true;
    }
    store.federation_transactions.push_back(std::move(transaction));
    return true;
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
    auto const [begin, end] = std::ranges::remove_if(
        store.federation_transactions, [transaction_id](PersistentFederationTransaction const& transaction) {
            return transaction.transaction_id == transaction_id;
        });
    store.federation_transactions.erase(begin, end);
    return true;
}

[[nodiscard]] auto store_room(PersistentStore& store, PersistentRoom room) -> bool
{
    if (room_exists(store, room.room_id))
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("insert_room", "INSERT INTO rooms VALUES ($1, $2)",
                                                    {
                                                        {room.room_id,         false},
                                                        {room.creator_user_id, false}
    })))
    {
        return false;
    }
    store.rooms.push_back(std::move(room));
    return true;
}

[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> MembershipStoreResult
{
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
    return MembershipStoreResult::stored;
}

[[nodiscard]] auto update_membership(PersistentStore& store, std::string_view room_id, std::string_view user_id,
                                     std::string_view new_membership) -> bool
{
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
    if (!record_and_persist(
            store, record_statement("update_membership",
                                    "UPDATE membership SET membership = $3 WHERE room_id = $1 AND user_id = $2",
                                    {
                                        {std::string{room_id},        false},
                                        {std::string{user_id},        false},
                                        {std::string{new_membership}, false}
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
    log_diagnostic("membership.updated", {
                                             {"room_id",    std::string{room_id},        false},
                                             {"user_id",    std::string{user_id},        false},
                                             {"membership", std::string{new_membership}, false}
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
                store, record_statement("insert_invite", "INSERT INTO invites VALUES ($1, $2, $3, $4, $5, $6, $7)",
                                        {public_value(invite.room_id), public_value(invite.user_id),
                                         public_value(invite.sender_user_id), public_value(invite.event_id),
                                         sensitive_value(invite.signed_event_json), sensitive_value(*invite_state_json),
                                         public_value(std::to_string(invite.stream_ordering))})))
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
            store, record_statement("update_invite",
                                    "UPDATE invites SET sender_user_id = $3, event_id = $4, signed_event_json = $5, "
                                    "invite_state_json = $6, stream_ordering = $7 WHERE room_id = $1 AND user_id = $2",
                                    {public_value(invite.room_id), public_value(invite.user_id),
                                     public_value(invite.sender_user_id), public_value(invite.event_id),
                                     sensitive_value(invite.signed_event_json), sensitive_value(*invite_state_json),
                                     public_value(std::to_string(invite.stream_ordering))})))
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
    auto const room_statement = record_statement("insert_room", "INSERT INTO rooms VALUES ($1, $2)",
                                                 {
                                                     {room.room_id,         false},
                                                     {room.creator_user_id, false}
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
    return true;
}

[[nodiscard]] auto store_event(PersistentStore& store, PersistentEvent event) -> bool
{
    if (event_exists(store, event.event_id))
    {
        return false;
    }
    auto statements = std::vector<PreparedStatement>{
        record_statement("insert_event", "INSERT INTO events VALUES ($1, $2, $3, $4, $5, $6)",
                         {{event.event_id, false},
                                                                                                {event.room_id, false},
                                                                                                {event.sender_user_id, false},
                                                                                                {event.json, true},
                                                                                                {std::to_string(event.depth), false},
                                                                                                {std::to_string(event.stream_ordering), false}}
                          )
    };
    append_event_graph_statements(statements, event);
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    append_event_graph_rows(store, event);
    store.events.push_back(std::move(event));
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
    if (existing != store.state.end())
    {
        if (!record_and_persist(
                store,
                record_statement(
                    "upsert_state",
                    "UPDATE current_state SET event_id = $4 WHERE room_id = $1 AND event_type = $2 AND state_key = $3",
                    {
                        {state.room_id,    false},
                        {state.event_type, false},
                        {state.state_key,  false},
                        {state.event_id,   false}
        })))
        {
            return false;
        }
        existing->event_id = state.event_id;
        return true;
    }
    if (!record_and_persist(store, record_statement("insert_state", "INSERT INTO current_state VALUES ($1, $2, $3, $4)",
                                                    {
                                                        {state.room_id,    false},
                                                        {state.event_type, false},
                                                        {state.state_key,  false},
                                                        {state.event_id,   false}
    })))
    {
        return false;
    }
    store.state.push_back(std::move(state));
    return true;
}

[[nodiscard]] auto store_event_with_state(PersistentStore& store, PersistentEvent event,
                                          std::optional<PersistentStateEvent> state) -> bool
{
    if (event_exists(store, event.event_id) || (state.has_value() && !state_matches_event(event, *state)))
    {
        log_diagnostic("event_state.rejected", {
                                                   {"event_id",  event.event_id,                                  false},
                                                   {"room_id",   event.room_id,                                   false},
                                                   {"sender",    event.sender_user_id,                            false},
                                                   {"has_state", state.has_value() ? "true" : "false",            false},
                                                   {"reason",    "duplicate event or state does not match event", false}
        });
        return false;
    }
    auto const event_statement = record_statement("insert_event", "INSERT INTO events VALUES ($1, $2, $3, $4, $5, $6)",
                                                  {
                                                      {event.event_id,                        false},
                                                      {event.room_id,                         false},
                                                      {event.sender_user_id,                  false},
                                                      {event.json,                            true },
                                                      {std::to_string(event.depth),           false},
                                                      {std::to_string(event.stream_ordering), false}
    });
    auto statements = std::vector<PreparedStatement>{event_statement};
    append_event_graph_statements(statements, event);
    auto const existing_state = state.has_value()
                                    ? std::ranges::find_if(store.state,
                                                           [&state](PersistentStateEvent const& current) {
                                                               return current.room_id == state->room_id &&
                                                                      current.event_type == state->event_type &&
                                                                      current.state_key == state->state_key;
                                                           })
                                    : store.state.end();
    if (state.has_value())
    {
        if (existing_state != store.state.end())
        {
            statements.push_back(record_statement(
                "upsert_state",
                "UPDATE current_state SET event_id = $4 WHERE room_id = $1 AND event_type = $2 AND state_key = $3",
                {
                    {state->room_id,    false},
                    {state->event_type, false},
                    {state->state_key,  false},
                    {state->event_id,   false}
            }));
        }
        else
        {
            statements.push_back(record_statement("insert_state", "INSERT INTO current_state VALUES ($1, $2, $3, $4)",
                                                  {
                                                      {state->room_id,    false},
                                                      {state->event_type, false},
                                                      {state->state_key,  false},
                                                      {state->event_id,   false}
            }));
        }
    }
    if (!commit_persistent_transaction(store, statements))
    {
        log_diagnostic("event_state.rejected", {
                                                   {"event_id",  event.event_id,                             false},
                                                   {"room_id",   event.room_id,                              false},
                                                   {"sender",    event.sender_user_id,                       false},
                                                   {"has_state", state.has_value() ? "true" : "false",       false},
                                                   {"reason",    "persistence backend rejected transaction", false}
        });
        return false;
    }
    log_diagnostic("event_state.persisted", {
                                                {"event_id",        event.event_id,                        false},
                                                {"room_id",         event.room_id,                         false},
                                                {"sender",          event.sender_user_id,                  false},
                                                {"depth",           std::to_string(event.depth),           false},
                                                {"stream_ordering", std::to_string(event.stream_ordering), false},
                                                {"has_state",       state.has_value() ? "true" : "false",  false}
    });
    append_event_graph_rows(store, event);
    store.events.push_back(std::move(event));
    if (state.has_value())
    {
        if (existing_state != store.state.end())
        {
            existing_state->event_id = state->event_id;
        }
        else
        {
            store.state.push_back(std::move(*state));
        }
    }
    return true;
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
    if (!record_and_persist(store,
                            record_statement("upsert_fallback_key",
                                             "INSERT INTO fallback_keys VALUES ($1, $2, $3, $4) ON CONFLICT (user_id, "
                                             "device_id, key_id) DO UPDATE SET json = $4",
                                             {public_value(key.user_id), public_value(key.device_id),
                                              public_value(key.key_id), sensitive_value(key.json)})))
    {
        return false;
    }
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
    auto const existing =
        std::ranges::find_if(store.key_signatures, [&signature](PersistentKeySignature const& current) {
            return current.signer_user_id == signature.signer_user_id &&
                   current.target_user_id == signature.target_user_id &&
                   current.target_device_id == signature.target_device_id;
        });
    if (existing != store.key_signatures.end())
    {
        existing->json = std::move(signature.json);
        return true;
    }
    store.key_signatures.push_back(std::move(signature));
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
    if (!record_and_persist(store,
                            record_statement("delete_key_backup_version",
                                             "DELETE FROM key_backup_versions WHERE user_id = $1 AND version = $2",
                                             {public_value(user_id), public_value(version)})))
    {
        return false;
    }
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

[[nodiscard]] auto delete_all_key_backup_sessions(PersistentStore& store, std::string_view user_id) -> bool
{
    if (!record_and_persist(store, record_statement("delete_all_key_backup_sessions",
                                                    "DELETE FROM key_backup_sessions WHERE user_id = $1",
                                                    {public_value(user_id)})))
    {
        return false;
    }
    std::erase_if(store.key_backup_sessions, [user_id](auto const& s) {
        return s.user_id == user_id;
    });
    return true;
}

[[nodiscard]] auto store_local_media(PersistentStore& store, PersistentLocalMedia media) -> bool
{
    if (!media_hash_is_valid(media.hash_algorithm, media.digest) || media.size_bytes == 0U)
    {
        return false;
    }
    auto const duplicate = std::ranges::any_of(store.local_media, [&media](PersistentLocalMedia const& existing) {
        return existing.media_id == media.media_id;
    });
    if (duplicate)
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("insert_media",
                                                    "INSERT INTO media VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                                                    {
                                                        {media.media_id,                       false},
                                                        {media.owner_user_id,                  false},
                                                        {media.content_type,                   false},
                                                        {std::to_string(media.size_bytes),     false},
                                                        {media.hash_algorithm,                 false},
                                                        {media.digest,                         false},
                                                        {media.quarantined ? "true" : "false", false},
                                                        {media.removed ? "true" : "false",     false}
    })))
    {
        return false;
    }
    store.local_media.push_back(std::move(media));
    return true;
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

[[nodiscard]] auto store_remote_media(PersistentStore& store, PersistentRemoteMedia media) -> bool
{
    auto const duplicate = std::ranges::any_of(store.remote_media, [&media](PersistentRemoteMedia const& existing) {
        return existing.server_name == media.server_name && existing.media_id == media.media_id;
    });
    if (duplicate)
    {
        return false;
    }
    if (!record_and_persist(store, record_statement("insert_remote_media",
                                                    "INSERT INTO remote_media VALUES ($1, $2, $3, $4, $5)",
                                                    {
                                                        {media.server_name,                    false},
                                                        {media.media_id,                       false},
                                                        {media.content_type,                   false},
                                                        {std::to_string(media.size_bytes),     false},
                                                        {media.quarantined ? "true" : "false", false}
    })))
    {
        return false;
    }
    store.remote_media.push_back(std::move(media));
    return true;
}

[[nodiscard]] auto store_media_blob(PersistentStore& store, PersistentMediaBlob blob) -> bool
{
    if (blob.storage_id.empty() || blob.hash_algorithm.empty() || blob.digest.empty())
    {
        return false;
    }
    if (!record_and_persist(
            store,
            record_statement("upsert_media_blob",
                             "INSERT INTO media_blobs VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (storage_id) DO "
                             "UPDATE SET hash_algorithm = $2, digest = $3, size_bytes = $4, bytes = $5, ref_count = $6",
                             {
                                 {blob.storage_id,                 false},
                                 {blob.hash_algorithm,             false},
                                 {blob.digest,                     false},
                                 {std::to_string(blob.size_bytes), false},
                                 {blob.bytes,                      true },
                                 {std::to_string(blob.ref_count),  false}
    })))
    {
        return false;
    }
    auto existing = std::ranges::find_if(store.media_blobs, [&blob](PersistentMediaBlob const& current) {
        return current.storage_id == blob.storage_id;
    });
    if (existing != store.media_blobs.end())
    {
        *existing = std::move(blob);
        return true;
    }
    store.media_blobs.push_back(std::move(blob));
    return true;
}

[[nodiscard]] auto append_audit_event(PersistentStore& store, PersistentAuditEvent event) -> bool
{
    if (!record_and_persist(store, record_statement("append_audit", "INSERT INTO audit_log VALUES ($1, $2, $3, $4, $5)",
                                                    {
                                                        {event.category,   false},
                                                        {event.event_type, false},
                                                        {event.actor,      false},
                                                        {event.target,     false},
                                                        {event.reason,     false}
    })))
    {
        return false;
    }
    store.audit_log.push_back(std::move(event));
    return true;
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

[[nodiscard]] auto store_account_data(PersistentStore& store, PersistentAccountData data) -> bool
{
    if (data.user_id.empty() || data.event_type.empty())
    {
        return false;
    }
    store.next_sync_stream_id += 1U;
    data.stream_id = store.next_sync_stream_id;
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
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    auto const existing = std::ranges::find_if(store.account_data, [&data](PersistentAccountData const& current) {
        return current.user_id == data.user_id && current.room_id == data.room_id &&
               current.event_type == data.event_type;
    });
    if (existing != store.account_data.end())
    {
        *existing = std::move(data);
        return true;
    }
    store.account_data.push_back(std::move(data));
    return true;
}

[[nodiscard]] auto enqueue_to_device_message(PersistentStore& store, PersistentToDeviceMessage message) -> bool
{
    if (message.sender_user_id.empty() || message.target_user_id.empty() || message.message_type.empty() ||
        message.content_json.empty())
    {
        return false;
    }
    store.next_sync_stream_id += 1U;
    message.stream_id = store.next_sync_stream_id;
    if (!record_and_persist(
            store,
            record_statement("insert_to_device_message",
                             "INSERT INTO to_device_messages (stream_id, sender_user_id, target_user_id, "
                             "target_device_id, message_type, content) VALUES ($1, $2, $3, $4, $5, $6)",
                             {public_value(std::to_string(message.stream_id)), public_value(message.sender_user_id),
                              public_value(message.target_user_id), public_value(message.target_device_id),
                              public_value(message.message_type), sensitive_value(message.content_json)})))
    {
        return false;
    }
    store.to_device_messages.push_back(std::move(message));
    return true;
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
    auto acknowledged = std::vector<PersistentToDeviceMessage>{};
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
        if (message.stream_id > since_stream_id)
        {
            drained.push_back(message);
        }
        else
        {
            acknowledged.push_back(message);
        }
    }
    // Purge acknowledged, device-targeted rows from both the in-memory mirror and
    // the backing store so the queue stays bounded. Broadcast (`*`/empty) rows are
    // shared across this user's devices and are not acknowledged per-device here,
    // so they are left in storage (filtered out of future syncs by the since
    // token) rather than deleted on one device's acknowledgement. Deletion is
    // scoped by stream_id so concurrent senders can't race a row in between.
    for (auto const& message : acknowledged)
    {
        auto const targeted_device = !message.target_device_id.empty() && message.target_device_id != "*";
        if (!targeted_device)
        {
            continue;
        }
        std::ignore = record_and_persist(
            store, record_statement("delete_to_device_message",
                                    "DELETE FROM to_device_messages WHERE stream_id = $1 AND target_user_id = $2 AND "
                                    "target_device_id = $3",
                                    {public_value(std::to_string(message.stream_id)),
                                     public_value(message.target_user_id), public_value(message.target_device_id)}));
        auto const [first, last] =
            std::ranges::remove_if(store.to_device_messages, [&message](PersistentToDeviceMessage const& candidate) {
                return candidate.stream_id == message.stream_id && candidate.target_user_id == message.target_user_id &&
                       candidate.target_device_id == message.target_device_id;
            });
        store.to_device_messages.erase(first, last);
    }
    return drained;
}

[[nodiscard]] auto record_device_list_change(PersistentStore& store, PersistentDeviceListChange change) -> bool
{
    if (change.observer_user_id.empty() || change.subject_user_id.empty())
    {
        return false;
    }
    if (change.change_type != "changed" && change.change_type != "left")
    {
        return false;
    }
    store.next_sync_stream_id += 1U;
    change.stream_id = store.next_sync_stream_id;
    if (!record_and_persist(
            store,
            record_statement("insert_device_list_change",
                             "INSERT INTO device_list_changes (stream_id, observer_user_id, subject_user_id, "
                             "change_type) VALUES ($1, $2, $3, $4)",
                             {public_value(std::to_string(change.stream_id)), public_value(change.observer_user_id),
                              public_value(change.subject_user_id), public_value(change.change_type)})))
    {
        return false;
    }
    store.device_list_changes.push_back(std::move(change));
    return true;
}

[[nodiscard]] auto upsert_presence(PersistentStore& store, PersistentPresence state) -> bool
{
    if (state.user_id.empty() || state.presence.empty())
    {
        return false;
    }
    store.next_sync_stream_id += 1U;
    state.stream_id = store.next_sync_stream_id;
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
    auto const statement = record_statement("insert_room_alias", "INSERT INTO room_aliases VALUES ($1, $2)",
                                            {public_value(alias.room_alias), public_value(alias.room_id)});
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

auto restore_sync_stream_id(PersistentStore& store) -> void
{
    auto observed = store.next_sync_stream_id;
    auto const consider = [&observed](std::uint64_t candidate) noexcept {
        if (candidate > observed)
        {
            observed = candidate;
        }
    };
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
    store.next_sync_stream_id = observed;
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
    auto const statement = record_statement(
        "upsert_profile",
        "INSERT INTO profiles (user_id, displayname, avatar_url) VALUES ($1, $2, $3) "
        "ON CONFLICT (user_id) DO UPDATE SET displayname = $2, avatar_url = $3",
        {public_value(profile.user_id), public_value(profile.displayname), public_value(profile.avatar_url)});
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
                                            std::string_view room_id, std::string_view event_type,
                                            std::string_view txn_id) -> std::optional<std::string>
{
    auto const it = std::ranges::find_if(store.client_txn_ids, [&](PersistentClientTxnRecord const& r) {
        return r.user_id == user_id && r.room_id == room_id && r.event_type == event_type && r.txn_id == txn_id;
    });
    if (it == store.client_txn_ids.end())
    {
        return std::nullopt;
    }
    return it->event_id;
}

[[nodiscard]] auto store_client_txn(PersistentStore& store, PersistentClientTxnRecord record) -> bool
{
    if (record.user_id.empty() || record.event_type.empty() || record.txn_id.empty())
    {
        return false;
    }
    // If already recorded (concurrent retry), the original wins — do not overwrite.
    if (find_client_txn_event_id(store, record.user_id, record.room_id, record.event_type, record.txn_id).has_value())
    {
        return true;
    }
    auto const statement =
        record_statement("insert_client_txn_id",
                         "INSERT INTO client_txn_ids (user_id, room_id, event_type, txn_id, event_id) "
                         "VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
                         {public_value(record.user_id), public_value(record.room_id), public_value(record.event_type),
                          public_value(record.txn_id), public_value(record.event_id)});
    if (!record_and_persist(store, statement))
    {
        return false;
    }
    store.client_txn_ids.push_back(std::move(record));
    return true;
}

[[nodiscard]] auto sensitive_values_are_redacted(PersistentStore const& store) noexcept -> bool
{
    for (auto const& statement : store.prepared_statements)
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
