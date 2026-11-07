// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// A checked `signed` object (SignedThirdPartyInvite): `mxid` is a valid user ID, `token` a non-empty string of at most
// 255 bytes, and `signatures` an object of at most 8 servers holding at most 8 string signatures each. Other members
// are kept, because the identity server's signature covers them. `json` is the canonical JSON of the whole object.
struct SignedThirdPartyInvite final
{
    std::string mxid{};
    std::string token{};
    std::string json{};
};

} // namespace merovingian::federation
