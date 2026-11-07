// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/RemoteOldVerifyKey.hpp"
#include "merovingian/federation/RemoteVerifyKey.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

// Parsed and self-verified result of fetching a remote server's keys.
struct RemoteKeyResponse final
{
    std::string server_name{};
    std::uint64_t valid_until_ts{0U};
    std::vector<RemoteVerifyKey> verify_keys{};
    // Well-formed `old_verify_keys` entries. A malformed entry is skipped on its
    // own; it never costs the response its `verify_keys`. cache_remote_server_keys
    // persists each as a retired row (`server_signing_keys.expired_ts`), so events
    // signed before a rotation verify from the cache with no further fetch.
    std::vector<RemoteOldVerifyKey> old_verify_keys{};
};

} // namespace merovingian::federation
