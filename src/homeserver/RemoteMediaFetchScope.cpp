// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/RemoteMediaFetchScope.hpp"

#include "merovingian/homeserver/RemoteMediaFetchMode.hpp"

#include <optional>
#include <utility>

namespace merovingian::homeserver
{

namespace
{
    // The innermost scope's state on this thread, held by value (ADR-0529).
    struct FetchState final
    {
        RemoteMediaFetchMode mode{RemoteMediaFetchMode::inline_fetch};
        bool deferred{false};
    };

    // Empty when no scope is open on this thread. Never shared between threads,
    // so it needs no synchronisation.
    [[nodiscard]] auto fetch_slot() noexcept -> std::optional<FetchState>&
    {
        thread_local auto slot = std::optional<FetchState>{};
        return slot;
    }
} // namespace

RemoteMediaFetchScope::RemoteMediaFetchScope(RemoteMediaFetchMode mode) noexcept
{
    auto const previous = std::exchange(fetch_slot(), FetchState{mode, false});
    if (previous.has_value())
    {
        m_previous_mode = previous->mode;
        m_previous_deferred = previous->deferred;
    }
}

RemoteMediaFetchScope::~RemoteMediaFetchScope()
{
    if (m_previous_mode.has_value())
    {
        fetch_slot() = FetchState{*m_previous_mode, m_previous_deferred};
    }
    else
    {
        fetch_slot().reset();
    }
}

auto RemoteMediaFetchScope::current_mode() noexcept -> RemoteMediaFetchMode
{
    auto const& slot = fetch_slot();
    return slot.has_value() ? slot->mode : RemoteMediaFetchMode::inline_fetch;
}

auto RemoteMediaFetchScope::record_deferral() noexcept -> bool
{
    auto& slot = fetch_slot();
    if (!slot.has_value() || slot->mode != RemoteMediaFetchMode::defer)
    {
        return false;
    }
    slot->deferred = true;
    return true;
}

auto RemoteMediaFetchScope::deferred() const noexcept -> bool
{
    auto const& slot = fetch_slot();
    return slot.has_value() && slot->deferred;
}

} // namespace merovingian::homeserver
