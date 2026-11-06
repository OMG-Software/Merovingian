// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncExtensionRequests.hpp"
#include "merovingian/sync/SlidingSyncList.hpp"
#include "merovingian/sync/SlidingSyncRoomSubscription.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace merovingian::sync
{

// MSC4186 §Request body
struct SlidingSyncRequest final
{
    // Client-chosen identifier; isolates connection state between concurrent clients.
    std::optional<std::string> conn_id{};
    std::map<std::string, SlidingSyncList> lists{};
    std::map<std::string, SlidingSyncRoomSubscription> room_subscriptions{};
    std::optional<SlidingSyncExtensionRequests> extensions{};
    // Newer MSC4186 drafts (and Element X) move pos and timeout into the body.
    // These are used when the query parameters are absent.
    std::optional<std::string> pos{};
    std::optional<std::uint64_t> timeout{};
    // MSC4186 request body `set_presence`, as sent. A value that is not a string is kept as the empty string, which
    // is no presence mode, so the handler answers it 400 M_INVALID_PARAM like any other unknown value.
    std::optional<std::string> set_presence{};
};

} // namespace merovingian::sync
