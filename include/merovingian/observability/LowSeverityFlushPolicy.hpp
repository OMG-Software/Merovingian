// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SingleLog by James Chapman, BSD-3-Clause.
#pragma once

#include <chrono>
#include <cstddef>
#include <optional>

namespace merovingian::observability
{

class LowSeverityFlushPolicy final
{
public:
    using Clock = std::chrono::steady_clock;

    [[nodiscard]] static constexpr auto message_interval() noexcept -> std::size_t
    {
        return 100U;
    }

    [[nodiscard]] static constexpr auto time_interval() noexcept -> Clock::duration
    {
        return std::chrono::seconds{1};
    }

    [[nodiscard]] auto observe_message(bool immediate_flush, Clock::time_point now) noexcept -> bool
    {
        if (immediate_flush)
        {
            mark_flushed();
            return true;
        }

        if (m_pending_count == 0U)
        {
            m_next_deadline = now + time_interval();
        }

        ++m_pending_count;
        if (m_pending_count >= message_interval() || flush_due(now))
        {
            mark_flushed();
            return true;
        }

        return false;
    }

    [[nodiscard]] auto flush_due(Clock::time_point now) const noexcept -> bool
    {
        return m_next_deadline.has_value() && now >= *m_next_deadline;
    }

    auto mark_flushed() noexcept -> void
    {
        m_pending_count = 0U;
        m_next_deadline.reset();
    }

    [[nodiscard]] auto pending_count() const noexcept -> std::size_t
    {
        return m_pending_count;
    }

    [[nodiscard]] auto next_deadline() const noexcept -> std::optional<Clock::time_point>
    {
        return m_next_deadline;
    }

private:
    std::size_t m_pending_count{0U};
    std::optional<Clock::time_point> m_next_deadline{};
};

} // namespace merovingian::observability
