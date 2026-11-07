// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SingleLog by James Chapman, BSD-3-Clause.
#pragma once

#include <cstddef>

namespace merovingian::observability
{

// L-10 / L-13 (security-audit-report-2026-09.md): tracks bounded-resource
// drop episodes so a caller can emit exactly one warning per contiguous run
// of drops rather than one per dropped item -- flooding a log/audit sink
// during an incident must not itself become the flood. Shared by
// `SingleLog::console_log`/`file_log` (a bounded queue silently discarding
// entries once full) and `local_audit_sink` in
// `src/homeserver/local_services.cpp` (silently no-opping while the
// thread-local database is unset/closed): both are "keep working, but tell
// the operator once" backpressure signals.
class DropEpisodePolicy final
{
public:
    // Call once per attempt. `accepted` is whether the attempt succeeded
    // (the queue had room / the audit sink persisted the event). Returns
    // true exactly once per drop episode: the first failed attempt after a
    // run of successes (or since construction). Every subsequent failed
    // attempt in the same episode returns false, so the caller emits at
    // most one warning per flood; a later success resets the episode so a
    // fresh flood warns again.
    [[nodiscard]] auto observe(bool accepted) noexcept -> bool
    {
        if (accepted)
        {
            m_in_drop_episode = false;
            return false;
        }

        ++m_dropped_total;
        auto const entering_episode = !m_in_drop_episode;
        m_in_drop_episode = true;
        return entering_episode;
    }

    [[nodiscard]] auto dropped_total() const noexcept -> std::size_t
    {
        return m_dropped_total;
    }

    [[nodiscard]] auto in_drop_episode() const noexcept -> bool
    {
        return m_in_drop_episode;
    }

private:
    std::size_t m_dropped_total{0U};
    bool m_in_drop_episode{false};
};

} // namespace merovingian::observability
