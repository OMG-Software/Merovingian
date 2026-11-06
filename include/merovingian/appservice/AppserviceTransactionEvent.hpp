// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::appservice
{

// One event in a `PUT /_matrix/app/v1/transactions/{txnId}` request body
// (Matrix v1.19 Application Service API §"Pushing events"). Mirrors the
// spec's `ClientEvent` shape. `content_json` is the pre-serialized `content`
// object (never re-parsed by the builder — the caller already has it from
// the persisted event).
struct AppserviceTransactionEvent final
{
    std::string content_json{}; // pre-serialized JSON object; empty means "{}"
    std::string event_id{};
    std::uint64_t origin_server_ts{0U};
    std::string room_id{};
    std::string sender{};
    std::optional<std::string> state_key{}; // present only for state events
    std::string type{};
};

} // namespace merovingian::appservice
