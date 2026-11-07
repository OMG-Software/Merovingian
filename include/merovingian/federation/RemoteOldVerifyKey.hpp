// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

// One `old_verify_keys` entry: a key the server no longer signs with, and when
// it stopped (server-server-api.md, Publishing keys). Valid only for events
// sent before `expired_ts`; never for a federation request.
struct RemoteOldVerifyKey final
{
    std::string key_id{};
    std::string public_key_base64{};
    std::uint64_t expired_ts{0U};
};

} // namespace merovingian::federation
