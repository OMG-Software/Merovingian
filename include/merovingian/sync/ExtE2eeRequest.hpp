// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtensionNames.hpp"

namespace merovingian::sync
{

// MSC4543 e2ee extension request.
struct ExtE2eeRequest final
{
    bool enabled{false};
    ExtensionNames names{};
};

} // namespace merovingian::sync
