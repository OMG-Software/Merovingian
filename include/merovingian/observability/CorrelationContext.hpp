// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::observability
{

struct CorrelationContext final
{
    std::string request_id{};
    std::string trace_id{};
    std::string span_id{};
};

} // namespace merovingian::observability
