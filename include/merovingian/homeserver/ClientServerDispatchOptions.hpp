// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/RemoteMediaFetchMode.hpp"

namespace merovingian::homeserver
{

// How handle_client_server_request runs one request.
struct ClientServerDispatchOptions final
{
    // A /sync with a timeout may answer needs_wait instead of blocking.
    bool can_wait{true};
    // How a remote media fetch may run (ADR-0121).
    RemoteMediaFetchMode remote_media{RemoteMediaFetchMode::inline_fetch};
    // The transport already counted this request against the rate limiter (the
    // media fetch pool running a deferred request again); do not count it twice.
    bool rate_limit_admitted{false};
};

} // namespace merovingian::homeserver
