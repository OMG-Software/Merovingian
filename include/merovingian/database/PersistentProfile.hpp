// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct PersistentProfile final
{
    std::string user_id{};
    std::string displayname{};
    std::string avatar_url{};
    // The extended profile fields (`m.tz` and custom keys, spec v1.16) as one canonical JSON object, the
    // text `{}` when there are none. displayname and avatar_url stay in their own columns.
    std::string fields_json{"{}"};
};

} // namespace merovingian::database
