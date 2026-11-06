// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/observability/observability_enums.hpp"

#include <string>

namespace merovingian::observability
{

struct AdminControlSurface final
{
    AdminSurface surface{AdminSurface::local_socket};
    std::string bind_address{};
    bool enabled{false};
    bool local_only{true};
    bool requires_admin_token{true};
    bool tls_required{false};
};

} // namespace merovingian::observability
