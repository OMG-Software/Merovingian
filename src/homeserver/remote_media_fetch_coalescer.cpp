// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/remote_media_fetch_coalescer.hpp"

#include <utility>

namespace merovingian::homeserver
{

RemoteMediaFetchCoalescer::Lead::Lead(RemoteMediaFetchCoalescer& coalescer, std::string key) noexcept
    : m_coalescer{coalescer}
    , m_key{std::move(key)}
{
}

RemoteMediaFetchCoalescer::Lead::Lead(Lead&& other) noexcept
    : m_coalescer{other.m_coalescer}
    , m_key{std::move(other.m_key)}
    , m_held{std::exchange(other.m_held, false)}
{
}

RemoteMediaFetchCoalescer::Lead::~Lead()
{
    if (m_held)
    {
        m_coalescer.release(m_key);
    }
}

auto RemoteMediaFetchCoalescer::try_lead(std::string key) -> std::optional<Lead>
{
    auto const lock = std::lock_guard{m_mutex};
    if (!m_leading.insert(key).second)
    {
        return std::nullopt;
    }
    return Lead{*this, std::move(key)};
}

auto RemoteMediaFetchCoalescer::wait_until_idle(std::string_view key, std::chrono::steady_clock::time_point deadline)
    -> bool
{
    auto const owned_key = std::string{key};
    auto lock = std::unique_lock{m_mutex};
    ++m_waiting;
    auto const idle = m_released.wait_until(lock, deadline, [this, &owned_key] {
        return !m_leading.contains(owned_key);
    });
    --m_waiting;
    return idle;
}

auto RemoteMediaFetchCoalescer::in_flight() const -> std::size_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_leading.size();
}

auto RemoteMediaFetchCoalescer::waiting() const -> std::size_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_waiting;
}

auto RemoteMediaFetchCoalescer::release(std::string const& key) noexcept -> void
{
    {
        auto const lock = std::lock_guard{m_mutex};
        m_leading.erase(key);
    }
    m_released.notify_all();
}

} // namespace merovingian::homeserver
