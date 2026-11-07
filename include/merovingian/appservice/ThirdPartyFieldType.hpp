// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::appservice
{

// A `field_types` entry of a `GET /_matrix/app/v1/thirdparty/protocol/{protocol}`
// response (Matrix v1.19 Application/Client-Server API "Third-party
// networks"/"Third-party Lookups"). Both members are opaque, untrusted
// strings supplied by the appservice — never interpreted, only bounded and
// echoed back to the client.
struct ThirdPartyFieldType final
{
    std::string placeholder{};
    std::string regexp{};
};

} // namespace merovingian::appservice
