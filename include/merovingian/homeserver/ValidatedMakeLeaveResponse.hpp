// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

#include <string>

namespace merovingian::homeserver
{

struct ValidatedMakeLeaveResponse final
{
    bool ok{false};
    std::string reason{};
    std::string room_version{};
    canonicaljson::Object event{};
};

} // namespace merovingian::homeserver
