// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/OAuthStore.hpp"

#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/OAuthTables.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <algorithm>
#include <span>
#include <string>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

namespace merovingian::database
{
namespace
{

    // A prepared statement takes at most 128 parameters, so a longer list of IDs is several DELETEs in the one
    // transaction, never one statement per row.
    constexpr auto delete_ids_per_statement = std::size_t{128U};

    [[nodiscard]] auto text(std::string_view value) -> BoundValue
    {
        return {std::string{value}, false};
    }

    [[nodiscard]] auto client_id_is_storable(std::string_view client_id) noexcept -> bool
    {
        return !client_id.empty() && client_id.size() <= max_oauth_client_id_bytes;
    }

    [[nodiscard]] auto delete_clients_statement(std::span<std::string const> client_ids) -> PreparedStatement
    {
        auto sql = std::string{"DELETE FROM oauth_clients WHERE client_id IN ("};
        auto parameters = std::vector<BoundValue>{};
        parameters.reserve(client_ids.size());
        for (auto const& client_id : client_ids)
        {
            sql += parameters.empty() ? "$" : ", $";
            sql += std::to_string(parameters.size() + 1U);
            parameters.push_back(text(client_id));
        }
        sql += ")";
        return {"delete_oauth_clients", std::move(sql), std::move(parameters)};
    }

} // namespace

auto store_oauth_client(PersistentStore& store, PersistentOAuthClient client) -> OAuthClientStoreResult
{
    if (!client_id_is_storable(client.client_id) || client.metadata_json.empty() ||
        client.metadata_json.size() > max_oauth_client_metadata_bytes)
    {
        return OAuthClientStoreResult::refused;
    }
    if (store.oauth.find_client(client.client_id) != nullptr)
    {
        return OAuthClientStoreResult::existing;
    }
    auto const statement = PreparedStatement{
        "insert_oauth_client",
        "INSERT INTO oauth_clients (client_id, metadata_json, created_at_ms, last_used_at_ms) VALUES ($1, $2, $3, $4)",
        {text(client.client_id), text(client.metadata_json), text(std::to_string(client.created_at_ms)),
          text(std::to_string(client.last_used_at_ms))}
    };
    if (!commit_persistent_transaction(store, {statement}))
    {
        return OAuthClientStoreResult::refused;
    }
    std::ignore = store.oauth.insert_client(std::move(client));
    return OAuthClientStoreResult::inserted;
}

auto find_oauth_client(PersistentStore const& store, std::string_view client_id) -> PersistentOAuthClient const*
{
    return store.oauth.find_client(client_id);
}

auto oauth_client_count(PersistentStore const& store) -> std::size_t
{
    return store.oauth.client_count();
}

auto touch_oauth_client(PersistentStore& store, std::string_view client_id, std::uint64_t now_ms) -> bool
{
    auto const* client = store.oauth.find_client(client_id);
    if (client == nullptr)
    {
        return false;
    }
    // A stored value from the future, or one inside the interval, is fresh enough: no write.
    if (now_ms <= client->last_used_at_ms || now_ms - client->last_used_at_ms <= oauth_client_touch_interval_ms)
    {
        return true;
    }
    auto const statement = PreparedStatement{
        "touch_oauth_client",
        "UPDATE oauth_clients SET last_used_at_ms = $1 WHERE client_id = $2",
        {text(std::to_string(now_ms)), text(client_id)}
    };
    if (!commit_persistent_transaction(store, {statement}))
    {
        return false;
    }
    std::ignore = store.oauth.set_client_last_used(client_id, now_ms);
    return true;
}

auto delete_oauth_clients(PersistentStore& store, std::span<std::string const> client_ids) -> bool
{
    if (client_ids.empty())
    {
        return true;
    }
    auto seen = std::unordered_set<std::string_view>{};
    for (auto const& client_id : client_ids)
    {
        if (!seen.insert(client_id).second || store.oauth.find_client(client_id) == nullptr ||
            store.oauth.sessions_of_client(client_id) != 0U)
        {
            return false;
        }
    }
    auto statements = std::vector<PreparedStatement>{};
    statements.reserve((client_ids.size() / delete_ids_per_statement) + 1U);
    for (auto first = std::size_t{0U}; first < client_ids.size(); first += delete_ids_per_statement)
    {
        auto const count = std::min(delete_ids_per_statement, client_ids.size() - first);
        statements.push_back(delete_clients_statement(client_ids.subspan(first, count)));
    }
    if (!commit_persistent_transaction(store, statements))
    {
        return false;
    }
    for (auto const& client_id : client_ids)
    {
        std::ignore = store.oauth.erase_client(client_id);
    }
    return true;
}

auto oauth_clients_without_sessions(PersistentStore const& store, std::size_t max, std::uint64_t used_before_ms,
                                    std::function<bool(std::string_view)> const& excluded) -> std::vector<std::string>
{
    return store.oauth.idle_clients(max, used_before_ms, excluded);
}

auto find_oauth_session(PersistentStore const& store, std::string_view user_id, std::string_view device_id)
    -> PersistentOAuthSession const*
{
    return store.oauth.find_session(user_id, device_id);
}

auto oauth_sessions_of_user(PersistentStore const& store, std::string_view user_id)
    -> std::vector<PersistentOAuthSession>
{
    return store.oauth.sessions_of_user(user_id);
}

auto oauth_client_has_session(PersistentStore const& store, std::string_view client_id) -> bool
{
    return store.oauth.sessions_of_client(client_id) != 0U;
}

auto prepare_oauth_session_insert(PersistentStore const& store, PersistentOAuthSession const& session,
                                  bool replaces_device_session) -> std::optional<PreparedStatement>
{
    if (session.user_id.empty() || session.device_id.empty() || !client_id_is_storable(session.client_id) ||
        session.scope.size() > max_oauth_scope_bytes || store.oauth.find_client(session.client_id) == nullptr ||
        (!replaces_device_session && store.oauth.find_session(session.user_id, session.device_id) != nullptr))
    {
        return std::nullopt;
    }
    return PreparedStatement{
        "insert_oauth_session",
        "INSERT INTO oauth_sessions (user_id, device_id, client_id, scope, created_at_ms) VALUES ($1, $2, $3, $4, $5)",
        {text(session.user_id), text(session.device_id), text(session.client_id), text(session.scope),
          text(std::to_string(session.created_at_ms))}
    };
}

auto remember_oauth_session(PersistentStore& store, PersistentOAuthSession session) -> bool
{
    return store.oauth.insert_session(std::move(session));
}

auto store_oauth_session(PersistentStore& store, PersistentOAuthSession session) -> bool
{
    auto statement = prepare_oauth_session_insert(store, session);
    if (!statement.has_value() || !commit_persistent_transaction(store, {std::move(*statement)}))
    {
        return false;
    }
    return remember_oauth_session(store, std::move(session));
}

auto delete_oauth_session(PersistentStore& store, std::string_view user_id, std::string_view device_id) -> bool
{
    if (store.oauth.find_session(user_id, device_id) == nullptr ||
        !commit_persistent_transaction(store, {delete_oauth_session_of_device_statement(user_id, device_id)}))
    {
        return false;
    }
    return store.oauth.erase_session(user_id, device_id);
}

auto delete_oauth_session_of_device_statement(std::string_view user_id, std::string_view device_id) -> PreparedStatement
{
    return {
        "delete_oauth_session_of_device",
        "DELETE FROM oauth_sessions WHERE user_id = $1 AND device_id = $2",
        {text(user_id), text(device_id)}
    };
}

} // namespace merovingian::database
