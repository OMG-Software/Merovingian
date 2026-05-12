// SPDX-License-Identifier: GPL-3.0-or-later

#include <algorithm>
#include <merovingian/database/persistent_store.hpp>
#include <optional>
#include <utility>

namespace merovingian::database
{
namespace
{

    [[nodiscard]] auto record_statement(std::string name, std::string sql, std::vector<BoundValue> parameters = {})
        -> PreparedStatement
    {
        return {std::move(name), std::move(sql), std::move(parameters)};
    }

    [[nodiscard]] auto token_is_hash(std::string_view token_hash) noexcept -> bool
    {
        return token_hash.starts_with("token-hash:v2:");
    }

    [[nodiscard]] auto media_hash_is_valid(std::string_view hash_algorithm, std::string_view digest) noexcept -> bool
    {
        return !hash_algorithm.empty() && !digest.empty() && digest.find('/') == std::string_view::npos;
    }

    [[nodiscard]] auto is_json_space(char value) noexcept -> bool
    {
        return value == ' ' || value == '\n' || value == '\r' || value == '\t';
    }

    [[nodiscard]] auto parse_json_string(std::string_view input, std::size_t& cursor) -> std::optional<std::string>
    {
        if (cursor >= input.size() || input[cursor] != '"')
        {
            return std::nullopt;
        }
        ++cursor;
        auto output = std::string{};
        while (cursor < input.size())
        {
            auto const character = input[cursor++];
            if (character == '"')
            {
                return output;
            }
            if (character == '\\')
            {
                if (cursor >= input.size())
                {
                    return std::nullopt;
                }
                auto const escaped = input[cursor++];
                if (escaped == '"' || escaped == '\\' || escaped == '/')
                {
                    output.push_back(escaped);
                }
                else if (escaped == 'n')
                {
                    output.push_back('\n');
                }
                else if (escaped == 'r')
                {
                    output.push_back('\r');
                }
                else if (escaped == 't')
                {
                    output.push_back('\t');
                }
                else
                {
                    return std::nullopt;
                }
            }
            else
            {
                output.push_back(character);
            }
        }
        return std::nullopt;
    }

    auto skip_json_space(std::string_view input, std::size_t& cursor) noexcept -> void
    {
        while (cursor < input.size() && is_json_space(input[cursor]))
        {
            ++cursor;
        }
    }

    [[nodiscard]] auto top_level_json_string_field(std::string_view json, std::string_view field_name)
        -> std::optional<std::string>
    {
        auto cursor = std::size_t{0U};
        skip_json_space(json, cursor);
        if (cursor >= json.size() || json[cursor] != '{')
        {
            return std::nullopt;
        }
        ++cursor;
        while (cursor < json.size())
        {
            skip_json_space(json, cursor);
            if (cursor < json.size() && json[cursor] == '}')
            {
                return std::nullopt;
            }
            auto const key = parse_json_string(json, cursor);
            if (!key.has_value())
            {
                return std::nullopt;
            }
            skip_json_space(json, cursor);
            if (cursor >= json.size() || json[cursor] != ':')
            {
                return std::nullopt;
            }
            ++cursor;
            skip_json_space(json, cursor);
            if (*key == field_name)
            {
                return parse_json_string(json, cursor);
            }
            if (!parse_json_string(json, cursor).has_value())
            {
                return std::nullopt;
            }
            skip_json_space(json, cursor);
            if (cursor < json.size() && json[cursor] == ',')
            {
                ++cursor;
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
    for (auto const& media : store.local_media)
    {
        if (!media_hash_is_valid(media.hash_algorithm, media.digest) || media.size_bytes == 0U)
        {
            return {false, "local media metadata is incomplete"};
        }
    }
    return {true, {}};
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
    store.prepared_statements.push_back(record_statement("insert_user", "INSERT INTO users VALUES ($1, $2, $3, $4, $5)",
                                                         {
                                                             {user.user_id,                      false},
                                                             {user.password_hash,                true },
                                                             {user.locked ? "true" : "false",    false},
                                                             {user.suspended ? "true" : "false", false},
                                                             {user.admin ? "true" : "false",     false}
    }));
    store.users.push_back(std::move(user));
    return true;
}

[[nodiscard]] auto store_device(PersistentStore& store, PersistentDevice device) -> bool
{
    auto const duplicate = std::ranges::any_of(store.devices, [&device](PersistentDevice const& existing) {
        return existing.user_id == device.user_id && existing.device_id == device.device_id;
    });
    if (duplicate)
    {
        return false;
    }
    store.prepared_statements.push_back(
        record_statement("insert_device", "INSERT INTO devices VALUES ($1, $2, $3)",
                         {
                             {device.user_id,      false},
                             {device.device_id,    false},
                             {device.display_name, false}
    }));
    store.devices.push_back(std::move(device));
    return true;
}

[[nodiscard]] auto store_access_token(PersistentStore& store, PersistentAccessToken token) -> bool
{
    if (!token_is_hash(token.token_hash))
    {
        return false;
    }
    auto const duplicate = std::ranges::any_of(store.access_tokens, [&token](PersistentAccessToken const& existing) {
        return existing.token_hash == token.token_hash;
    });
    if (duplicate)
    {
        return false;
    }
    store.prepared_statements.push_back(record_statement("insert_access_token",
                                                         "INSERT INTO access_tokens VALUES ($1, $2, $3, $4)",
                                                         {
                                                             {token.user_id,                    false},
                                                             {token.device_id,                  false},
                                                             {token.token_hash,                 true },
                                                             {token.revoked ? "true" : "false", false}
    }));
    store.access_tokens.push_back(std::move(token));
    return true;
}

[[nodiscard]] auto revoke_access_token(PersistentStore& store, std::string_view token_hash) -> std::size_t
{
    store.prepared_statements.push_back(record_statement("revoke_access_token",
                                                         "UPDATE access_tokens SET revoked = $1 WHERE token_hash = $2",
                                                         {
                                                             {"true",                  false},
                                                             {std::string{token_hash}, true }
    }));
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

[[nodiscard]] auto store_room(PersistentStore& store, PersistentRoom room) -> bool
{
    store.prepared_statements.push_back(record_statement("insert_room", "INSERT INTO rooms VALUES ($1, $2)",
                                                         {
                                                             {room.room_id,         false},
                                                             {room.creator_user_id, false}
    }));
    store.rooms.push_back(std::move(room));
    return true;
}

[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> bool
{
    store.prepared_statements.push_back(
        record_statement("insert_membership", "INSERT INTO membership VALUES ($1, $2)",
                         {
                             {membership.room_id, false},
                             {membership.user_id, false}
    }));
    store.memberships.push_back(std::move(membership));
    return true;
}

[[nodiscard]] auto store_event(PersistentStore& store, PersistentEvent event) -> bool
{
    store.prepared_statements.push_back(record_statement(
        "insert_event", "INSERT INTO events VALUES ($1, $2, $3, $4)",
        {
            {event.event_id,       false},
            {event.room_id,        false},
            {event.sender_user_id, false},
            {event.json,           true }
    }));
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
        existing->event_id = state.event_id;
        store.prepared_statements.push_back(record_statement(
            "upsert_state",
            "UPDATE current_state SET event_id = $4 WHERE room_id = $1 AND event_type = $2 AND state_key = $3",
            {
                {state.room_id,    false},
                {state.event_type, false},
                {state.state_key,  false},
                {state.event_id,   false}
        }));
        return true;
    }
    store.prepared_statements.push_back(record_statement(
        "insert_state", "INSERT INTO current_state VALUES ($1, $2, $3, $4)",
        {
            {state.room_id,    false},
            {state.event_type, false},
            {state.state_key,  false},
            {state.event_id,   false}
    }));
    store.state.push_back(std::move(state));
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
    store.prepared_statements.push_back(record_statement("insert_media",
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
    }));
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
    existing->quarantined = quarantined;
    existing->removed = removed;
    store.prepared_statements.push_back(
        record_statement("update_media_state", "UPDATE media SET quarantined = $2, removed = $3 WHERE media_id = $1",
                         {
                             {std::string{media_id},          false},
                             {quarantined ? "true" : "false", false},
                             {removed ? "true" : "false",     false}
    }));
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
    store.prepared_statements.push_back(record_statement("insert_remote_media",
                                                         "INSERT INTO remote_media VALUES ($1, $2, $3, $4, $5)",
                                                         {
                                                             {media.server_name,                    false},
                                                             {media.media_id,                       false},
                                                             {media.content_type,                   false},
                                                             {std::to_string(media.size_bytes),     false},
                                                             {media.quarantined ? "true" : "false", false}
    }));
    store.remote_media.push_back(std::move(media));
    return true;
}

[[nodiscard]] auto append_audit_event(PersistentStore& store, PersistentAuditEvent event) -> bool
{
    store.prepared_statements.push_back(record_statement("append_audit",
                                                         "INSERT INTO audit_log VALUES ($1, $2, $3, $4, $5)",
                                                         {
                                                             {event.category,   false},
                                                             {event.event_type, false},
                                                             {event.actor,      false},
                                                             {event.target,     false},
                                                             {event.reason,     false}
    }));
    store.audit_log.push_back(std::move(event));
    return true;
}

[[nodiscard]] auto append_admin_action(PersistentStore& store, PersistentAdminAction action) -> bool
{
    store.prepared_statements.push_back(
        record_statement("append_admin_action", "INSERT INTO admin_actions VALUES ($1, $2, $3)",
                         {
                             {action.admin_user_id, false},
                             {action.action,        false},
                             {action.target,        false}
    }));
    store.admin_actions.push_back(std::move(action));
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

} // namespace merovingian::database
