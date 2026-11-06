// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>

namespace merovingian::sync
{

// MSC4186 §rooms[roomId] hero — a notable room member shown in the room name.
struct SlidingSyncHero final
{
    std::string user_id{};
    std::optional<std::string> display_name{};
    std::optional<std::string> avatar_url{};
};

} // namespace merovingian::sync
