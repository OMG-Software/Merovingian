// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::platform
{

struct RandomSourcePlan final
{
    std::string source_path{"/dev/urandom"};
    bool require_nonblocking{true};
    bool fail_if_unavailable{true};
};

} // namespace merovingian::platform
