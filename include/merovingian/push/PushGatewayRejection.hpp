// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::push
{

// Parsed `200` response to `/notify`: the list of pushkeys the gateway
// rejects as permanently invalid.
struct PushGatewayRejection final
{
    std::vector<std::string> rejected_pushkeys{};
};

} // namespace merovingian::push
