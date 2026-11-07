// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// What a remote-media request carries beyond the media it names. Ignored for
// media hosted on this server.
struct RemoteMediaRequestContext final
{
    // The client the request is attributed to (rate_limit_client_key), which the
    // per-client cap of the client-outbound budget counts under (ADR-0079).
    // "unknown" is what a request with no peer address is keyed as.
    std::string client_key{"unknown"};
    // The authenticated user, empty when the request carries no valid token.
    // The per-requester thumbnail decode cap (MED-4) counts under it, or under
    // client_key when it is empty.
    std::string requester{};
    // The `allow_remote` query parameter (default true). False means the caller
    // does not want this server to go and fetch remote media (OUT-7).
    bool allow_remote{true};
    // ADR-0212: the `timeout_ms` query parameter (spec default 20000): how long
    // a download of a reserved but not yet uploaded local media ID may wait.
    // Capped by security.media.pending_upload_max_wait_ms.
    std::uint32_t timeout_ms{20000U};
};

} // namespace merovingian::homeserver
