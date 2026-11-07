// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/PendingStreamOrdering.hpp"

#include <cstdint>
#include <optional>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// ADR-0247, ADR-0437: a PendingStreamOrdering whose end also tells the syncs waiting on the
// event stream. Ending a reservation can move the visible position past later events already
// applied, whether its own event was applied or its commit failed. If the visible position is then
// above this ordering, events were held behind it whose writers' scoped publishes ran too early
// (they saw a lower position), so it broadcasts. Otherwise it moves the positions with an empty
// scope and wakes no user: the event's own scoped publish (the `pdu_sink`) wakes its audience, and
// a failed commit has nothing to announce. No wake-up is lost: an event not visible at its own
// publish is above some pending ordering, and when the last such ordering ends `visible` reaches
// that event, above the ordering just released, so that release broadcasts. Use it on every path
// that commits with runtime.mutex released; the path publishes its own scoped wake after the event
// is applied. Its destructor takes runtime.mutex itself (it is recursive), so it may end with a
// room stripe held.
class PublishedStreamOrdering final
{
public:
    PublishedStreamOrdering(HomeserverRuntime& runtime, std::uint64_t ordering);
    ~PublishedStreamOrdering() noexcept;

    PublishedStreamOrdering(PublishedStreamOrdering const&) = delete;
    auto operator=(PublishedStreamOrdering const&) -> PublishedStreamOrdering& = delete;
    PublishedStreamOrdering(PublishedStreamOrdering&&) = delete;
    auto operator=(PublishedStreamOrdering&&) -> PublishedStreamOrdering& = delete;

private:
    HomeserverRuntime& m_runtime;
    std::uint64_t m_ordering;
    std::optional<PendingStreamOrdering> m_pending;
};

} // namespace merovingian::homeserver
