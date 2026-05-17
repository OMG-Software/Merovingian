// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/outbound_transaction.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Outbound make_join / make_leave / make_knock GET. Returns an OutboundCall
// preconfigured for the target endpoint; the caller dispatches through
// `perform_outbound_transaction` (or the dispatch worker for retry-aware
// delivery).
[[nodiscard]] auto make_outbound_make_membership(FederationEndpoint endpoint, std::string_view destination,
                                                 std::string_view origin, std::string_view room_id,
                                                 std::string_view user_id,
                                                 std::vector<std::string> const& supported_room_versions)
    -> OutboundTransaction;

// Outbound send_join / send_leave / send_knock PUT carrying a signed
// membership event body. `endpoint` selects which spec path is used; the
// v2 paths are preferred where applicable.
[[nodiscard]] auto make_outbound_send_membership(FederationEndpoint endpoint, std::string_view destination,
                                                 std::string_view origin, std::string_view room_id,
                                                 std::string_view event_id, std::string_view signed_event_json)
    -> OutboundTransaction;

// Outbound invite. `room_version`, the signed invite event JSON, and any
// state events the inviter wants the invitee to see are composed into the
// v2 invite body. When `room_version` is empty the helper emits the v1
// invite shape (the body IS the event).
[[nodiscard]] auto make_outbound_invite(std::string_view destination, std::string_view origin,
                                        std::string_view room_id, std::string_view event_id,
                                        std::string_view room_version, std::string_view signed_invite_event_json,
                                        std::vector<std::string> const& invite_room_state_json)
    -> OutboundTransaction;

// Outbound backfill GET. `event_ids` are sent as repeated `v=` query
// parameters; `limit` is appended when non-zero.
[[nodiscard]] auto make_outbound_backfill(std::string_view destination, std::string_view origin,
                                          std::string_view room_id, std::vector<std::string> const& event_ids,
                                          std::size_t limit) -> OutboundTransaction;

} // namespace merovingian::federation
