// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/PublicRoomsFilter.hpp"

#include <cstddef>
#include <optional>
#include <string>

namespace merovingian::federation
{

struct PublicRoomsRequest final
{
    PublicRoomsFilter filter{};
    // Absent: the request set no limit (or `limit=0`, the spec's "no limit"). The server still pages.
    std::optional<std::size_t> limit{};
    std::size_t since_offset{0U};
    bool include_all_networks{false};
    std::string third_party_instance_id{};
};

} // namespace merovingian::federation
