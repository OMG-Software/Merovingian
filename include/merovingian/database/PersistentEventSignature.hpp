// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentEventSignature final
{
    std::string event_id{};
    std::string server_name{};
    std::string key_id{};
    std::string signature{};
};

} // namespace merovingian::database
