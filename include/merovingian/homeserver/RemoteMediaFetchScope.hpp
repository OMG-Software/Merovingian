// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/homeserver/RemoteMediaFetchMode.hpp"

#include <optional>

namespace merovingian::homeserver
{

// Publishes the remote media fetch mode for this thread's in-flight request, so
// the fetch deep in the media service learns it without the mode being threaded
// through the client-server dispatcher and the local router. The publication is
// thread_local, like `RequestLockScope`: one request thread never observes
// another's. The innermost scope wins and restores its predecessor on exit.
//
// The thread's slot holds the innermost scope's mode and deferral by value, and
// each scope keeps the values it displaced (ADR-0529). No address of a scope is
// stored anywhere: a scope is a local variable, and a published pointer to it
// would be a stack address in thread-local storage (CodeQL
// cpp/stack-address-escape).
class RemoteMediaFetchScope final
{
public:
    explicit RemoteMediaFetchScope(RemoteMediaFetchMode mode) noexcept;
    ~RemoteMediaFetchScope();
    RemoteMediaFetchScope(RemoteMediaFetchScope const&) = delete;
    auto operator=(RemoteMediaFetchScope const&) -> RemoteMediaFetchScope& = delete;
    RemoteMediaFetchScope(RemoteMediaFetchScope&&) = delete;
    auto operator=(RemoteMediaFetchScope&&) -> RemoteMediaFetchScope& = delete;

    // The mode of this thread's innermost scope; inline_fetch when there is none.
    [[nodiscard]] static auto current_mode() noexcept -> RemoteMediaFetchMode;

    // Records on this thread's innermost scope that its request must be handed
    // to the media fetch pool. True when recorded: only a scope in defer mode
    // records a deferral.
    [[nodiscard]] static auto record_deferral() noexcept -> bool;

    // Whether a deferral was recorded on this scope. Read it while this scope is
    // the thread's innermost, as its owner does once the calls it made return:
    // the flag lives in the thread's slot, which an inner scope still open holds.
    [[nodiscard]] auto deferred() const noexcept -> bool;

private:
    // What the thread's slot held before this scope opened, put back when it
    // closes: no mode when no scope was open.
    std::optional<RemoteMediaFetchMode> m_previous_mode{};
    bool m_previous_deferred{false};
};

} // namespace merovingian::homeserver
