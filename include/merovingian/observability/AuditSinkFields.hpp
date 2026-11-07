// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from SingleLog by James Chapman, BSD-3-Clause.
#pragma once

#include "merovingian/observability/AuditCategory.hpp"

#include <string_view>

namespace merovingian::observability
{

struct AuditSinkFields final
{
    AuditCategory category{AuditCategory::auth};
    std::string_view event_type{};
    std::string_view actor{};
    std::string_view target{};
    std::string_view reason{};
};

} // namespace merovingian::observability
