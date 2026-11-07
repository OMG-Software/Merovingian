// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/ThirdPartyBindNotification.hpp"

#include <optional>
#include <string>

namespace merovingian::federation
{

struct ThirdPartyBindParse final
{
    std::optional<ThirdPartyBindNotification> notification{};
    std::string reason{};
};

} // namespace merovingian::federation
