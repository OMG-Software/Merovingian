// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentOneTimeKey final
{
    std::string user_id{};
    std::string device_id{};
    std::string key_id{};
    std::string json{};
};

} // namespace merovingian::database
