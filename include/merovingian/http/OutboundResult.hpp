// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/OutboundResponse.hpp"
#include "merovingian/http/outbound_error.hpp"

#include <string>

namespace merovingian::http
{

struct OutboundResult final
{
    bool ok{false};
    OutboundResponse response{};
    OutboundError error{OutboundError::network_error};
    std::string error_detail{};
};

} // namespace merovingian::http
