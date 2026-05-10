// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/persistent_store.hpp>

#include <algorithm>
#include <utility>

namespace merovingian::database
{
namespace
{

[[nodiscard]] auto record_statement(std::string name, std::string sql, std::vector<BoundValue> parameters = {}) -> PreparedStatement
{
    return {std::move(name), std::move(sql), std::move(parameters)};
}

[[nodiscard]] auto token_is_hash(std::string_view token_hash) noexcept -> bool
{
    return token_hash.starts_with("token-hash:") || token_hash.starts_with("token-hash:v1:");
}

[[nodiscard]] auto json_has_string_field(std::string_view json, std::string_view field_name, std::string_view value) -> bool
{
    auto const needle = "\"" + std::string{field_name} + "\":\"" + std::string{value} + "\"";
    return json.find(needle) != std::string_view::npos;
}

[[nodiscard]] auto state_matches_persisted_event(PersistentStore const& store, PersistentStateEvent const& state) -> bool
{
    auto const iterator = std::ranges::find_if(store.events, [&state](PersistentEvent const& event) {
        return event.event_id == state.event_id && event.room_id == state.room_id
            && json_has_string_field(event.json, "type", state.event_type)
            && json_has_string_field(event.json, "state_key", state.state_key);
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
    return {true, {}};
}

[[nodiscard]] auto store_user(PersistentStore& store, PersistentUser user) -> bool
{
    store.prepared_statements.push_back(record_statement("insert_user", "INSERT INTO users VALUES ($1, $2, $3, $4, $5)", {{user.user_id, false}, {user.password_hash, true}, {user.locked ? "true" : "false", false}, {user.suspended ? "true" : "false", false}, {user.admin ? "true" : "false", false}}));
    auto const duplicate = std::ranges::any_of(store.users, [&user](PersistentUser const& existing) { return existing.user_id == user.user_id; });
    if (duplicate)
    {
        return false;
    }
    store.users.push_back(std::move(user));
    return true;
}

[[nodiscard]] auto store_device(PersistentStore& store, PersistentDevice device) -> bool
{
    store.prepared_statements.push_back(record_statement("insert_device", "INSERT INTO devices VALUES ($1, $2, $3)", {{device.user_id, false}, {device.device_id, false}, {device.display_name, false}}));
    auto const duplicate = std::ranges::any_of(store.devices, [&device](PersistentDevice const& existing) { return existing.user_id == device.user_id && existing.device_id == device.device_id; });
    if (duplicate)
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
    store.prepared_statements.push_back(record_statement("insert_access_token", "INSERT INTO access_tokens VALUES ($1, $2, $3, $4)", {{token.user_id, false}, {token.device_id, false}, {token.token_hash, true}, {token.revoked ? "true" : "false", false}}));
    store.access_tokens.push_back(std::move(token));
    return true;
}

[[nodiscard]] auto revoke_access_token(PersistentStore& store, std::string_view token_hash) -> std::size_t
{
    store.prepared_statements.push_back(record_statement("revoke_access_token", "UPDATE access_tokens SET revoked = $1 WHERE token_hash = $2", {{"true", false}, {std::string{token_hash}, true}}));
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
    store.prepared_statements.push_back(record_statement("insert_room", "INSERT INTO rooms VALUES ($1, $2)", {{room.room_id, false}, {room.creator_user_id, false}}));
    store.rooms.push_back(std::move(room));
    return true;
}

[[nodiscard]] auto store_membership(PersistentStore& store, PersistentMembership membership) -> bool
{
    store.prepared_statements.push_back(record_statement("insert_membership", "INSERT INTO membership VALUES ($1, $2)", {{membership.room_id, false}, {membership.user_id, false}}));
    store.memberships.push_back(std::move(membership));
    return true;
}

[[nodiscard]] auto store_event(PersistentStore& store, PersistentEvent event) -> bool
{
    store.prepared_statements.push_back(record_statement("insert_event", "INSERT INTO events VALUES ($1, $2, $3, $4)", {{event.event_id, false}, {event.room_id, false}, {event.sender_user_id, false}, {event.json, true}}));
    store.events.push_back(std::move(event));
    return true;
}

[[nodiscard]] auto store_state(PersistentStore& store, PersistentStateEvent state) -> bool
{
    if (!state_matches_persisted_event(store, state))
    {
        return false;
    }
    store.prepared_statements.push_back(record_statement("insert_state", "INSERT INTO current_state VALUES ($1, $2, $3, $4)", {{state.room_id, false}, {state.event_type, false}, {state.state_key, false}, {state.event_id, false}}));
    store.state.push_back(std::move(state));
    return true;
}

[[nodiscard]] auto append_audit_event(PersistentStore& store, PersistentAuditEvent event) -> bool
{
    store.prepared_statements.push_back(record_statement("append_audit", "INSERT INTO audit_log VALUES ($1, $2, $3, $4, $5)", {{event.category, false}, {event.event_type, false}, {event.actor, false}, {event.target, false}, {event.reason, false}}));
    store.audit_log.push_back(std::move(event));
    return true;
}

[[nodiscard]] auto append_admin_action(PersistentStore& store, PersistentAdminAction action) -> bool
{
    store.prepared_statements.push_back(record_statement("append_admin_action", "INSERT INTO admin_actions VALUES ($1, $2, $3)", {{action.admin_user_id, false}, {action.action, false}, {action.target, false}}));
    store.admin_actions.push_back(std::move(action));
    return true;
}

[[nodiscard]] auto sensitive_values_are_redacted(PersistentStore const& store) noexcept -> bool
{
    for (auto const& statement : store.prepared_statements)
    {
        for (auto const& value : statement.parameters)
        {
            if ((value.value.find("token") != std::string::npos || value.value.find("secret") != std::string::npos) && !value.sensitive)
            {
                return false;
            }
        }
    }
    return true;
}

} // namespace merovingian::database
