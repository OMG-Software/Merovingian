// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/http/connection_limiter.hpp"

#include <utility>

namespace merovingian::http
{

ConnectionLimiter::Slot::Slot(ConnectionLimiter& limiter, std::string key) noexcept
    : m_limiter{limiter}
    , m_key{std::move(key)}
{
}

ConnectionLimiter::Slot::Slot(Slot&& other) noexcept
    : m_limiter{other.m_limiter}
    , m_key{std::move(other.m_key)}
    , m_held{std::exchange(other.m_held, false)}
{
}

ConnectionLimiter::Slot::~Slot()
{
    if (m_held)
    {
        m_limiter.release(m_key);
    }
}

auto ConnectionLimiter::try_acquire(std::string key, std::uint32_t cap) -> std::optional<Slot>
{
    auto const lock = std::lock_guard{m_mutex};
    auto& count = m_counts[key];
    if (count >= cap)
    {
        if (count == 0U)
        {
            // A cap of 0 must not leave an empty entry behind.
            m_counts.erase(key);
        }
        return std::nullopt;
    }
    ++count;
    return Slot{*this, std::move(key)};
}

auto ConnectionLimiter::active(std::string_view key) const -> std::uint32_t
{
    auto const lock = std::lock_guard{m_mutex};
    auto const it = m_counts.find(std::string{key});
    return it == m_counts.end() ? 0U : it->second;
}

auto ConnectionLimiter::tracked_keys() const -> std::size_t
{
    auto const lock = std::lock_guard{m_mutex};
    return m_counts.size();
}

auto ConnectionLimiter::release(std::string const& key) noexcept -> void
{
    auto const lock = std::lock_guard{m_mutex};
    auto const it = m_counts.find(key);
    if (it == m_counts.end())
    {
        return;
    }
    if (it->second <= 1U)
    {
        m_counts.erase(it);
        return;
    }
    --it->second;
}

} // namespace merovingian::http
