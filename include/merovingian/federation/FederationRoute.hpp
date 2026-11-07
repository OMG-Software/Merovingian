// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/FederationEndpoint.hpp"

#include <string>

namespace merovingian::federation
{

struct FederationRoute final
{
    std::string method{};
    std::string path_template{};
    FederationEndpoint endpoint{FederationEndpoint::transaction};
    bool requires_request_signature{true};
    bool requires_event_signatures{true};
};

} // namespace merovingian::federation
