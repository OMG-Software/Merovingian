// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

namespace merovingian::federation
{

// What a client `POST /keys/claim` takes from one remote server's answer.
struct RemoteKeyClaimKeys final
{
    // User ID -> device ID -> key ID -> key, for requested users and devices only.
    canonicaljson::Object one_time_keys{};
};

} // namespace merovingian::federation
