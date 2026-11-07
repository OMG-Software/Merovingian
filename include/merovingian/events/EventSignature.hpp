// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::events
{

struct EventSignature final
{
    std::string server_name{};
    std::string key_id{};
    std::string signature{};
};

} // namespace merovingian::events
