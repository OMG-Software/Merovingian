// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// Parsed fields from an Authorization: X-Matrix ... header.
struct XMatrixCredentials final
{
    std::string origin{};
    std::string destination{};
    std::string key_id{};
    std::string signature{};
};

} // namespace merovingian::federation
