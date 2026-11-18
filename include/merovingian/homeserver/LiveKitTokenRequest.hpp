// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::homeserver
{

// An MSC4195 `get_token` request body, read and bounded (ADR-0829). Nothing in it is trusted: the caller judges every
// field against this server's own configuration and room state.
struct LiveKitTokenRequest final
{
    // The SFU the client means; only ever compared with `server.rtc.livekit.url` (or passed on unread when relayed).
    std::string url{};
    std::string room_id{};
    std::string slot_id{};
    std::string member_id{};
    // Client form only: the server whose SFU the token is for. Empty when the body did not name one.
    std::string server_name{};
    // Federation form only: the user the requesting server asks for.
    std::string user_id{};
};

} // namespace merovingian::homeserver
