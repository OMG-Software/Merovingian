// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/UserCodeAttemptThrottle.hpp"

namespace merovingian::homeserver
{

auto UserCodeAttemptThrottle::erase_ended(std::uint64_t now_ms) -> void
{
    while (!m_by_end.empty() && m_by_end.begin()->first.first <= now_ms)
    {
        m_windows.erase(m_by_end.begin()->second);
        m_by_end.erase(m_by_end.begin());
    }
}

auto UserCodeAttemptThrottle::blocked_for_ms(std::string_view client_key, std::uint64_t now_ms)
    -> std::optional<std::uint64_t>
{
    erase_ended(now_ms);
    if (auto const window = m_windows.find(client_key); window != m_windows.end())
    {
        if (window->second.wrong >= max_wrong_codes)
        {
            return window->second.ends_at_ms - now_ms;
        }
        return std::nullopt;
    }
    if (m_windows.size() >= max_addresses && !m_by_end.empty())
    {
        return m_by_end.begin()->first.first - now_ms;
    }
    return std::nullopt;
}

auto UserCodeAttemptThrottle::record_wrong(std::string_view client_key, std::uint64_t now_ms) -> bool
{
    erase_ended(now_ms);
    auto window = m_windows.find(client_key);
    if (window == m_windows.end())
    {
        if (m_windows.size() >= max_addresses)
        {
            return false;
        }
        auto const fresh = Window{now_ms + window_ms, m_next_sequence++, 0U};
        window = m_windows.emplace(std::string{client_key}, fresh).first;
        m_by_end.emplace(Order{fresh.ends_at_ms, fresh.sequence}, std::string{client_key});
    }
    if (window->second.wrong >= max_wrong_codes)
    {
        return false;
    }
    ++window->second.wrong;
    return window->second.wrong == max_wrong_codes;
}

auto UserCodeAttemptThrottle::size() const noexcept -> std::size_t
{
    return m_windows.size();
}

} // namespace merovingian::homeserver
