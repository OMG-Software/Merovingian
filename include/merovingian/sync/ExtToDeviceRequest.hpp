// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::sync
{

// MSC4186 §extensions.to_device
struct ExtToDeviceRequest final
{
    bool enabled{false};
    std::uint64_t limit{20U};
    // Opaque position from a prior to_device response (next_batch).
    std::optional<std::string> since{};
};

} // namespace merovingian::sync
