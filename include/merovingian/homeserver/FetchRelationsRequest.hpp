// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct FetchRelationsRequest final
{
    std::string room_id{};
    std::string event_id{};
    std::optional<std::string> rel_type{};
    std::optional<std::string> event_type{};
    std::optional<std::string> dir{};
    std::optional<std::string> from{};
    std::optional<std::uint64_t> limit{};
    std::optional<bool> recurse{};
    std::optional<std::string> to{};
};

} // namespace merovingian::homeserver
