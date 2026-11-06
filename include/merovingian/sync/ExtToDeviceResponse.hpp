// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::sync
{

struct ExtToDeviceResponse final
{
    std::vector<std::string> events_json{};
    // Opaque position for the next to_device request (since field).
    std::string next_batch{};
};

} // namespace merovingian::sync
