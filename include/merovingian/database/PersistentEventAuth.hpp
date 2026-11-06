// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentEventAuth final
{
    std::string event_id{};
    std::string auth_event_id{};
};

} // namespace merovingian::database
