// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <string>

namespace merovingian::appservice
{

// One entry of a `GET /_matrix/app/v1/thirdparty/user[/{protocol}]`
// response array (spec `User` object).
struct ThirdPartyUser final
{
    std::string userid{};
    canonicaljson::Object fields{};
    std::string protocol{};
};

} // namespace merovingian::appservice
