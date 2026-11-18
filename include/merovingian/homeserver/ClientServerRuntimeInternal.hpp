// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/OperationResult.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// Module-internal: what `ClientServerRuntime.cpp` keeps in its anonymous namespace and `DelayedEvents.cpp` (delayed
// events, MSC4140, ADR-0825) needs as well, so that a delayed event is judged and sent as the ordinary `/send` and
// `/state` routes would judge and send it, never by a copy. Each function is a call-through to the one the routes
// use, defined in `ClientServerRuntime.cpp`. Not public API.

// The answers the `/send` route gives for an event type or a transaction ID over 255 bytes
// (`client_txn_part_is_too_long`): 413 M_TOO_LARGE for the type, 400 M_INVALID_PARAM for the transaction ID. The route
// and the delayed events' schedule-time check both read their reasons here.
inline constexpr auto event_type_too_long_reason = std::string_view{"the event type is at most 255 bytes"};
inline constexpr auto txn_id_too_long_reason = std::string_view{"the transaction ID is at most 255 bytes"};

// True when `part` is over the 255 bytes an event type or a transaction ID may have where it is part of an idempotency
// key.
[[nodiscard]] auto event_txn_part_is_too_long(std::string_view part) noexcept -> bool;

// The rate-limit route template of `target` (its path with the identifiers replaced, `.../send/{eventType}/{txnId}`),
// the bucket name every request for the route shares; `/_matrix/client/{unmatched}` for a path the server does not
// serve. The query string is ignored.
[[nodiscard]] auto rate_limit_route_template(std::string_view target) -> std::string;

// The event body (`{"type", "content", "state_key"?}`) the `/send` and `/state` routes build from a request body, or
// nullopt when `content` is not a JSON object.
[[nodiscard]] auto route_event_body(std::string_view event_type, std::string_view content,
                                    std::optional<std::string> state_key = std::nullopt) -> std::optional<std::string>;

// The Matrix errcode the dispatcher gives a refusal of `status` that names none (403 M_FORBIDDEN, 404 M_NOT_FOUND, 401
// M_UNKNOWN_TOKEN, else M_UNKNOWN).
[[nodiscard]] auto errcode_for_refusal_status(std::uint16_t status) -> std::string_view;

} // namespace merovingian::homeserver
