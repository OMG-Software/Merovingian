// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::trust_safety
{

struct SafetyReportRequest final
{
    std::string reporter_user_id{};
    std::string room_id{};
    std::string event_id{};
    std::string reason{};
    std::int32_t score{0};
};

} // namespace merovingian::trust_safety
