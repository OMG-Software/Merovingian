// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §extensions.typing
struct ExtTypingRequest final
{
    bool enabled{false};
    // Limit typing delivery to these rooms; empty = all rooms in the response.
    std::vector<std::string> rooms{};
};

} // namespace merovingian::sync
