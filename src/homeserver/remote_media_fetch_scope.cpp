// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/remote_media_fetch_scope.hpp"

namespace merovingian::homeserver
{

namespace
{
    // The innermost scope published on this thread. Never shared between
    // threads, so it needs no synchronisation.
    thread_local RemoteMediaFetchScope* current_scope = nullptr;
} // namespace

RemoteMediaFetchScope::RemoteMediaFetchScope(RemoteMediaFetchMode mode) noexcept
    : m_mode{mode}
    , m_previous{current_scope}
{
    current_scope = this;
}

RemoteMediaFetchScope::~RemoteMediaFetchScope()
{
    current_scope = m_previous;
}

auto RemoteMediaFetchScope::current_mode() noexcept -> RemoteMediaFetchMode
{
    return current_scope == nullptr ? RemoteMediaFetchMode::inline_fetch : current_scope->m_mode;
}

auto RemoteMediaFetchScope::record_deferral() noexcept -> bool
{
    if (current_scope == nullptr || current_scope->m_mode != RemoteMediaFetchMode::defer)
    {
        return false;
    }
    current_scope->m_deferred = true;
    return true;
}

auto RemoteMediaFetchScope::deferred() const noexcept -> bool
{
    return m_deferred;
}

} // namespace merovingian::homeserver
