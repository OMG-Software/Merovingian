// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <compare>
#include <string>

namespace merovingian::push
{

// One email pusher: the user and the pusher's pushkey (the address as the client registered it).
struct EmailDigestKey final
{
    std::string user_id{};
    std::string pushkey{};

    auto operator<=>(EmailDigestKey const&) const = default;
};

} // namespace merovingian::push
