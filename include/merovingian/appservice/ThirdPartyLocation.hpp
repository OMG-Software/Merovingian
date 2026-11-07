// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <string>

namespace merovingian::appservice
{

// One entry of a `GET /_matrix/app/v1/thirdparty/location[/{protocol}]`
// response array (spec `Location` object).
struct ThirdPartyLocation final
{
    std::string alias{};
    canonicaljson::Object fields{};
    std::string protocol{};
};

} // namespace merovingian::appservice
