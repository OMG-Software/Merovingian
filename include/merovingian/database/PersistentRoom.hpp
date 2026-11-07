// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentRoom final
{
    std::string room_id{};
    std::string creator_user_id{};
    bool directory_public{false};
};

} // namespace merovingian::database
