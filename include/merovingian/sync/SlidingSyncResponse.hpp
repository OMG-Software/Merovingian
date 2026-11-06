// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncExtensionResponses.hpp"
#include "merovingian/sync/SlidingSyncListResponse.hpp"
#include "merovingian/sync/SlidingSyncRoomResponse.hpp"

#include <map>
#include <optional>
#include <string>

namespace merovingian::sync
{

// MSC4186 §Response body
struct SlidingSyncResponse final
{
    // Opaque position token; returned as ?pos= on the next request.
    std::string pos{};
    std::map<std::string, SlidingSyncListResponse> lists{};
    std::map<std::string, SlidingSyncRoomResponse> rooms{};
    std::optional<SlidingSyncExtensionResponses> extensions{};
};

} // namespace merovingian::sync
