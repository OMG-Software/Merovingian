// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::rooms
{

struct EncryptedEventLogSummary final
{
    std::string event_type{};
    std::string room_id{};
    std::string sender{};
    std::string payload{};
};

} // namespace merovingian::rooms
