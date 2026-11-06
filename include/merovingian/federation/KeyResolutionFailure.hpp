// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <string>

namespace merovingian::federation
{

// Negative cache entry: an origin whose key resolution failed, remembered until
// `expires_at` so repeats of the same name are cheap.
struct KeyResolutionFailure final
{
    std::string origin{};
    // Scoped to the requested key ID as well as the origin. Keying on the origin
    // alone let an unauthenticated sender poison a legitimate third party: name a
    // real server with a bogus key_id, the resolver fetches that server's real
    // keys successfully but returns nothing for the bogus id, and an
    // origin-scoped failure entry then rejects that server's genuine requests
    // for the whole TTL. A bogus key ID must only ever poison itself.
    std::string key_id{};
    std::chrono::steady_clock::time_point expires_at{};
};

} // namespace merovingian::federation
