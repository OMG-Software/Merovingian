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

} // namespace merovingian::homeserver
