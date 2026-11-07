// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::identity
{

// Parsed `POST /_matrix/identity/v2/lookup` response (200): the MXID bound to
// the 3PID. Empty `mxid` means the IS has no binding for the 3PID.
struct LookupResponse final
{
    std::string mxid{};
};

} // namespace merovingian::identity
