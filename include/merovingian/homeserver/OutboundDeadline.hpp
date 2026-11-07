// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>

namespace merovingian::homeserver
{

// A wall-clock deadline fixed when it is constructed. Discovery and each
// request that follows draw from the same one, so a slow first step shortens
// the next rather than adding to it.
class OutboundDeadline final
{
public:
    explicit OutboundDeadline(std::uint32_t budget_seconds) noexcept
        : m_end{std::chrono::steady_clock::now() + std::chrono::seconds{budget_seconds}}
    {
    }

    // Whole seconds left, rounded up so a sub-second remainder still allows a
    // request; 0 once the deadline has passed.
    [[nodiscard]] auto remaining_seconds() const noexcept -> std::uint32_t
    {
        auto const now = std::chrono::steady_clock::now();
        if (now >= m_end)
        {
            return 0U;
        }
        auto const left = std::chrono::duration_cast<std::chrono::milliseconds>(m_end - now).count();
        return static_cast<std::uint32_t>((left + 999) / 1000);
    }

    [[nodiscard]] auto expired() const noexcept -> bool
    {
        return std::chrono::steady_clock::now() >= m_end;
    }

    // The deadline itself, for a wait that must end with it.
    [[nodiscard]] auto end() const noexcept -> std::chrono::steady_clock::time_point
    {
        return m_end;
    }

private:
    std::chrono::steady_clock::time_point m_end;
};

} // namespace merovingian::homeserver
