// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/http/connection_limiter.hpp"

#include <tuple>
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
    std::ignore = cap;
    return Slot{*this, std::move(key)};
}

auto ConnectionLimiter::active(std::string_view key) const -> std::uint32_t
{
    std::ignore = key;
    return 0U;
}

auto ConnectionLimiter::tracked_keys() const -> std::size_t
{
    return 0U;
}

auto ConnectionLimiter::release(std::string const& key) noexcept -> void
{
    std::ignore = key;
}

} // namespace merovingian::http
