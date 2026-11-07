// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/StructuredLogField.hpp"

#include <string>
#include <vector>

namespace merovingian::observability
{

struct StructuredLogEvent final
{
    std::string logger{};
    std::string level{};
    std::vector<StructuredLogField> fields{};
};

} // namespace merovingian::observability
