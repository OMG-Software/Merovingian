// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::crypto
{

struct RandomBytesResult final
{
    std::string bytes{};
    std::string error{};
};

} // namespace merovingian::crypto
