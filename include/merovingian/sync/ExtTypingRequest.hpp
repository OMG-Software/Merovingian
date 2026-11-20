// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtensionNames.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §extensions.typing
struct ExtTypingRequest final
{
    bool enabled{false};
    // MSC4508's scope (`sync::extension_scope_rooms`, ADR-0861): the lists and room subscriptions the extension applies
    // to, by list key and room ID. Absent is every one; an empty array is none; "*" is every one (the older MSC3575
    // form). A room named in `rooms` without a subscription is not in scope.
    std::optional<std::vector<std::string>> lists{};
    std::optional<std::vector<std::string>> rooms{};
    ExtensionNames names{};
};

} // namespace merovingian::sync
