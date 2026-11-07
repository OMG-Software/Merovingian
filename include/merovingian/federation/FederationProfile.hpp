// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// Result of a federation `query/profile` lookup. found=false means the user
// is unknown to this server and the handler responds 404 M_NOT_FOUND.
struct FederationProfile final
{
    bool found{false};
    std::string displayname{};
    std::string avatar_url{};
    // The extended fields (`m.tz` and custom keys) as one canonical JSON object; empty or `{}` for none.
    std::string fields_json{};
};

} // namespace merovingian::federation
