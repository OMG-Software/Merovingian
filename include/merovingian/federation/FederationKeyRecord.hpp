// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct FederationKeyRecord final
{
    std::string server_name{};
    std::string key_id{};
    std::uint64_t valid_until_ts{0U};
    // Raw 32-byte Ed25519 public key (not base64) used to verify signatures
    // produced by this server. Populated from the remote's published
    // /_matrix/key/v2/server response.
    std::string public_key_bytes{};
    // True for a key published under `old_verify_keys`: "only valid for signing
    // events" (server-server-api.md, Publishing keys). It never authenticates a
    // federation request, and it verifies an event only when the event's
    // origin_server_ts is before `expired_ts`. For such a key `valid_until_ts`
    // equals `expired_ts` (capped at the time the key was fetched).
    bool retired{false};
    std::uint64_t expired_ts{0U};
};

} // namespace merovingian::federation
