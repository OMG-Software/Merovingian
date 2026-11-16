// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/OAuthTables.hpp"

#include <utility>

namespace merovingian::database
{
namespace
{

    // A key made of the user and the device, separated by NUL, which no Matrix identifier may hold.
    [[nodiscard]] auto session_key(std::string_view user_id, std::string_view device_id) -> std::string
    {
        auto key = std::string{user_id};
        key.push_back('\0');
        key.append(device_id);
        return key;
    }

} // namespace

auto OAuthTables::find_client(std::string_view client_id) const -> PersistentOAuthClient const*
{
    auto const found = clients_.find(client_id);
    return found == clients_.end() ? nullptr : &found->second;
}

auto OAuthTables::sessions_of_client(std::string_view client_id) const -> std::size_t
{
    auto const found = sessions_by_client_.find(client_id);
    return found == sessions_by_client_.end() ? 0U : found->second;
}

auto OAuthTables::mark_idle(PersistentOAuthClient const& client) -> void
{
    idle_.emplace(client.last_used_at_ms, client.client_id);
}

auto OAuthTables::unmark_idle(PersistentOAuthClient const& client) -> void
{
    idle_.erase({client.last_used_at_ms, client.client_id});
}

auto OAuthTables::insert_client(PersistentOAuthClient client) -> bool
{
    if (clients_.contains(client.client_id))
    {
        return false;
    }
    auto const idle = sessions_of_client(client.client_id) == 0U;
    auto key = client.client_id;
    auto const [position, inserted] = clients_.emplace(std::move(key), std::move(client));
    if (inserted && idle)
    {
        mark_idle(position->second);
    }
    return inserted;
}

auto OAuthTables::set_client_last_used(std::string_view client_id, std::uint64_t last_used_at_ms) -> bool
{
    auto const found = clients_.find(client_id);
    if (found == clients_.end())
    {
        return false;
    }
    auto const idle = sessions_of_client(client_id) == 0U;
    if (idle)
    {
        unmark_idle(found->second);
    }
    found->second.last_used_at_ms = last_used_at_ms;
    if (idle)
    {
        mark_idle(found->second);
    }
    return true;
}

auto OAuthTables::erase_client(std::string_view client_id) -> bool
{
    auto const found = clients_.find(client_id);
    if (found == clients_.end() || sessions_of_client(client_id) != 0U)
    {
        return false;
    }
    unmark_idle(found->second);
    clients_.erase(found);
    return true;
}

auto OAuthTables::idle_clients(std::size_t max, std::uint64_t used_before_ms,
                               std::function<bool(std::string_view)> const& excluded) const -> std::vector<std::string>
{
    auto chosen = std::vector<std::string>{};
    auto walked = std::uint64_t{0U};
    for (auto const& [last_used_at_ms, client_id] : idle_)
    {
        if (chosen.size() >= max || last_used_at_ms >= used_before_ms)
        {
            break;
        }
        ++walked;
        if (excluded && excluded(client_id))
        {
            continue;
        }
        chosen.push_back(client_id);
    }
    rows_examined_.add(walked);
    return chosen;
}

auto OAuthTables::find_session(std::string_view user_id, std::string_view device_id) const
    -> PersistentOAuthSession const*
{
    auto const found = sessions_.find(session_key(user_id, device_id));
    return found == sessions_.end() ? nullptr : &found->second;
}

auto OAuthTables::sessions_of_user(std::string_view user_id) const -> std::vector<PersistentOAuthSession>
{
    auto rows = std::vector<PersistentOAuthSession>{};
    auto const devices = devices_by_user_.find(user_id);
    if (devices == devices_by_user_.end())
    {
        return rows;
    }
    rows.reserve(devices->second.size());
    for (auto const& device_id : devices->second)
    {
        if (auto const* session = find_session(user_id, device_id); session != nullptr)
        {
            rows.push_back(*session);
        }
    }
    rows_examined_.add(devices->second.size());
    return rows;
}

auto OAuthTables::insert_session(PersistentOAuthSession session) -> bool
{
    auto key = session_key(session.user_id, session.device_id);
    if (sessions_.contains(key))
    {
        return false;
    }
    auto& count = sessions_by_client_[session.client_id];
    if (count == 0U)
    {
        if (auto const* client = find_client(session.client_id); client != nullptr)
        {
            unmark_idle(*client);
        }
    }
    ++count;
    devices_by_user_[session.user_id].insert(session.device_id);
    sessions_.emplace(std::move(key), std::move(session));
    return true;
}

auto OAuthTables::erase_session(std::string_view user_id, std::string_view device_id) -> bool
{
    auto const found = sessions_.find(session_key(user_id, device_id));
    if (found == sessions_.end())
    {
        return false;
    }
    auto const client_id = found->second.client_id;
    if (auto const devices = devices_by_user_.find(user_id); devices != devices_by_user_.end())
    {
        devices->second.erase(std::string{device_id});
        if (devices->second.empty())
        {
            devices_by_user_.erase(devices);
        }
    }
    sessions_.erase(found);
    if (auto const count = sessions_by_client_.find(client_id); count != sessions_by_client_.end())
    {
        if (--count->second == 0U)
        {
            sessions_by_client_.erase(count);
            if (auto const* client = find_client(client_id); client != nullptr)
            {
                mark_idle(*client);
            }
        }
    }
    return true;
}

auto OAuthTables::clear() noexcept -> void
{
    clients_.clear();
    sessions_.clear();
    devices_by_user_.clear();
    sessions_by_client_.clear();
    idle_.clear();
}

} // namespace merovingian::database
