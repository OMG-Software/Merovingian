// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// A refused request: always 400, with this standard error.
struct PublicRoomsRefusal final
{
    std::string errcode{};
    std::string message{};
};

} // namespace merovingian::federation
