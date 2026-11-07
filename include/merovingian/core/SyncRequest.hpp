// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::core
{

struct SyncRequest final
{
    std::optional<std::string> since{};
    std::optional<std::uint64_t> timeout{};
    std::optional<bool> full_state{};
    std::optional<std::string> filter{};
    // GET /sync `set_presence`, as sent (validated by the caller: it is client input).
    std::optional<std::string> set_presence{};
};

} // namespace merovingian::core
