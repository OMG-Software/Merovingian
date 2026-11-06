// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

struct PersistentMembership final
{
    std::string room_id{};
    std::string user_id{};
    std::string membership{"join"};
    std::uint64_t stream_ordering{0U};
};

} // namespace merovingian::database
