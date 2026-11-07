// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::events
{

struct EventHashResult final
{
    std::string sha256{};
    std::string error{};
};

} // namespace merovingian::events
