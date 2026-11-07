// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/PushGatewayCounts.hpp"
#include "merovingian/push/PushGatewayDevice.hpp"

#include <string>
#include <vector>

namespace merovingian::push
{

// Everything needed to build one `POST /_matrix/push/v1/notify` request body
// (docs/matrix-v1.19-spec/push-gateway-api.md). `content_json` is the
// pre-serialized `content` field of the event, already omitted by the caller
// when the format is `event_id_only` or the event has no content; empty
// means "omit `content`".
struct PushGatewayNotification final
{
    std::string event_id{};
    std::string room_id{};
    std::string room_alias{};
    std::string room_name{};
    std::string type{};
    std::string sender{};
    std::string sender_display_name{};
    bool user_is_target{false};
    std::string prio{"high"};
    std::string content_json{};
    PushGatewayCounts counts{};
    std::vector<PushGatewayDevice> devices{};
};

} // namespace merovingian::push
