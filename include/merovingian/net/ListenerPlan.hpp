// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/net/ListenerRole.hpp"

#include <string>

namespace merovingian::net
{

struct ListenerPlan final
{
    ListenerRole role{ListenerRole::client};
    std::string bind{};
    bool tls{false};
    bool reverse_proxy{true};
    std::string tls_certificate_file{};
    std::string tls_private_key_file{};
};

} // namespace merovingian::net
