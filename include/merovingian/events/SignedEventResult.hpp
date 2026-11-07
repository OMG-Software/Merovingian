// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::events
{

struct SignedEventResult final
{
    std::string event_json{};
    std::string server_name{};
    std::string key_id{};
    std::string signature{};
    std::string error{};
};

} // namespace merovingian::events
