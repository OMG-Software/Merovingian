// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct MigrationValidationResult final
{
    bool valid{false};
    std::string reason{};
};

} // namespace merovingian::database
