// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::platform
{

// One unveil(2) call: a path and its permissions ("rx", "rwc" or "r").
struct UnveilRule final
{
    std::string path{};
    std::string permissions{};

    auto operator==(UnveilRule const&) const -> bool = default;
};

} // namespace merovingian::platform
