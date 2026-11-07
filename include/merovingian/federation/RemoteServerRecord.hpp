// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::federation
{

struct RemoteServerRecord final
{
    std::string server_name{};
    std::string well_known_host{};
    std::string resolved_host{};
    std::vector<std::string> resolved_addresses{};
    bool tls_required{true};
};

} // namespace merovingian::federation
