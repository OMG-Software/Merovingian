// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

namespace merovingian::federation
{

// The keys a remote server returned from
// `POST /_matrix/federation/v1/user/keys/query`, reduced to what it may
// speak for. Each member is keyed by user ID, as in the response.
struct RemoteKeyQueryKeys final
{
    canonicaljson::Object device_keys{};
    canonicaljson::Object master_keys{};
    canonicaljson::Object self_signing_keys{};
};

} // namespace merovingian::federation
