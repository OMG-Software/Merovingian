// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// One verify key entry returned by GET /_matrix/key/v2/server. Mirrors the
// per-entry shape from the canonical Matrix server-key response.
struct RemoteVerifyKey final
{
    std::string key_id{};
    std::string public_key_base64{};
};

} // namespace merovingian::federation
