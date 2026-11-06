// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::trust_safety
{

// A report about a user (CS API `POST /users/{userId}/report`, v1.14).
struct UserReportRequest final
{
    std::string reporter_user_id{};
    std::string reported_user_id{};
    std::string reason{};
};

} // namespace merovingian::trust_safety
