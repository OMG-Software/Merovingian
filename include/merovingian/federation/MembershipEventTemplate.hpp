// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

// Templates returned by the make_join / make_leave / make_knock endpoints.
// The resident server populates the spec-required template fields and the
// remote peer signs the template before submitting it through
// send_join / send_leave / send_knock.
struct MembershipEventTemplate final
{
    std::string room_id{};
    std::string user_id{};
    std::string membership{};   // "join" | "leave" | "knock"
    std::string room_version{}; // actual room version read from m.room.create
    std::string origin{};       // resident server returning the template
    std::int64_t origin_server_ts{0};
    std::vector<std::string> prev_events{};
    std::vector<std::string> auth_events{};
    std::int64_t depth{0};
    std::string content_json{}; // canonical JSON object for content
    // When not empty, the request is refused: `reason` is the response body
    // (a Matrix error object) and `error_status` its HTTP status, e.g. 400
    // M_UNABLE_TO_AUTHORISE_JOIN or 403 M_FORBIDDEN for a restricted room the
    // user may not join (server-server-api.md "Restricted rooms").
    std::string reason{};
    std::uint16_t error_status{400U};
};

} // namespace merovingian::federation
