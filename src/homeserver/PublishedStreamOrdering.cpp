// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/PublishedStreamOrdering.hpp"

#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/sync/SyncNotifier.hpp"

#include <cstdint>
#include <mutex>

namespace merovingian::homeserver
{

PublishedStreamOrdering::PublishedStreamOrdering(HomeserverRuntime& runtime, std::uint64_t ordering)
    : m_runtime{runtime}
    , m_ordering{ordering}
    , m_pending{std::in_place, runtime.database, ordering}
{
}

PublishedStreamOrdering::~PublishedStreamOrdering() noexcept
{
    try
    {
        auto const lock = std::lock_guard{m_runtime.mutex};
        m_pending.reset();
        if (m_runtime.sync_notifier != nullptr)
        {
            // The event stream only: a sync stream ID is the caller's to publish once its event is
            // applied. Events held behind this ordering have just become visible, and their writers'
            // scoped publishes ran before they were: a broadcast. Otherwise only the positions move.
            auto const visible = visible_stream_position(m_runtime.database);
            if (visible > m_ordering)
            {
                m_runtime.sync_notifier->publish(visible, 0U);
            }
            else
            {
                m_runtime.sync_notifier->publish(visible, 0U, sync::AffectedUsers{});
            }
        }
    }
    catch (...)
    {
        // The reservation still ended with m_pending; only this wake-up is lost,
        // and the next publish delivers it.
    }
}

} // namespace merovingian::homeserver
