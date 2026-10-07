// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

namespace merovingian::homeserver
{

// How a remote media fetch may run on this thread (ADR-0121).
enum class RemoteMediaFetchMode
{
    // Fetch here, under the ADR-0079 main-pool budget. The default when nothing
    // is published: tests, embedded callers, and a server with no media pool.
    inline_fetch,
    // A main-pool request with a media fetch pool behind it. A fetch that would
    // go to the network records a deferral instead, and the transport hands the
    // request to the media fetch pool.
    defer,
    // The media fetch pool, running a request the transport already admitted.
    // Fetch here, without an ADR-0079 slot: the media pool's admission
    // replaces it.
    admitted,
};

// Publishes the remote media fetch mode for this thread's in-flight request, so
// the fetch deep in the media service learns it without the mode being threaded
// through the client-server dispatcher and the local router. The publication is
// thread_local, like `RequestLockScope`: one request thread never observes
// another's. The innermost scope wins and restores its predecessor on exit.
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

    [[nodiscard]] auto deferred() const noexcept -> bool;

private:
    RemoteMediaFetchMode m_mode;
    RemoteMediaFetchScope* m_previous{nullptr};
    bool m_deferred{false};
};

} // namespace merovingian::homeserver
