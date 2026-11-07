// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentKeyBackupSession final
{
    std::string user_id{};
    std::string version{};
    std::string room_id{};
    std::string session_id{};
    std::string json{};
};

} // namespace merovingian::database
