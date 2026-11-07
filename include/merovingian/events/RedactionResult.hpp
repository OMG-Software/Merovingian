// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"

#include <string>

namespace merovingian::events
{

struct RedactionResult final
{
    canonicaljson::Value event{};
    std::string error{};
};

} // namespace merovingian::events
