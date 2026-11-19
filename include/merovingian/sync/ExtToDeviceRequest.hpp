// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/ExtensionNames.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::sync
{

// MSC4538 to-device extension request.
struct ExtToDeviceRequest final
{
    bool enabled{false};
    // MSC4538: "Must be a positive integer. Defaults to 100."
    std::uint64_t limit{100U};
    // The request gave a `limit` that is not a positive integer: 400 M_BAD_JSON (MSC4538).
    bool limit_refused{false};
    // Opaque position from a prior to_device response (next_batch).
    std::optional<std::string> since{};
    ExtensionNames names{};
};

} // namespace merovingian::sync
