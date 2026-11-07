// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/BackfillRequest.hpp"
#include "merovingian/federation/BackfillResult.hpp"
#include "merovingian/federation/FederationEndpoint.hpp"
#include "merovingian/federation/FederationQueryPolicy.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/InviteAcceptResult.hpp"
#include "merovingian/federation/InviteRequest.hpp"
#include "merovingian/federation/MembershipAcceptResult.hpp"
#include "merovingian/federation/MembershipEventTemplate.hpp"
#include "merovingian/federation/MembershipPathParams.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

[[nodiscard]] auto parse_membership_path(FederationEndpoint endpoint, std::string_view target)
    -> std::optional<MembershipPathParams>;

// Hook signature for building a membership event template. Implementations
// query the persistent store for room state and produce a partial event
// matching the Matrix make_join / make_leave / make_knock spec.
using MembershipTemplateProvider = std::function<std::optional<MembershipEventTemplate>(
    FederationEndpoint endpoint, std::string_view room_id, std::string_view user_id,
    std::vector<std::string> const& supported_room_versions)>;

// Hook signature for accepting a signed membership event. The implementation
// runs auth-rules, persists the event, and returns the auth chain + state
// snapshot expected by the corresponding send_* response.
using MembershipAcceptor =
    std::function<MembershipAcceptResult(FederationEndpoint endpoint, std::string_view room_id,
                                         std::string_view event_id, InboundPduEnvelope const& envelope)>;

using InviteHandler = std::function<InviteAcceptResult(InviteRequest const&)>;

using BackfillProvider = std::function<BackfillResult(BackfillRequest const&)>;

// Parses the v1 backfill query string (?v=eventId&v=eventId&limit=N). Returns
// nullopt when the input is malformed (e.g. limit not numeric).
// The parsed `limit` is clamped to the configured server policy so a remote
// cannot ask the injected BackfillProvider for an unbounded number of PDUs.
[[nodiscard]] auto parse_backfill_query(std::string_view target,
                                        FederationQueryPolicy const& policy = FederationQueryPolicy{})
    -> std::optional<BackfillRequest>;

[[nodiscard]] auto parse_invite_body(std::string_view body, std::string_view room_id, std::string_view event_id,
                                     FederationEndpoint endpoint) -> std::optional<InviteRequest>;

} // namespace merovingian::federation
