// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/transactions.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Parsed components of a membership endpoint URI. The federation router has
// already validated that the target matches the route's path template and
// segment count, so the suffix splits cleanly on '/'. Empty fields signal a
// malformed target.
struct MembershipPathParams final
{
    std::string room_id{};
    // For make_*: this is the user_id segment.
    // For send_* and invite: this is the event_id segment.
    std::string subject{};
};

[[nodiscard]] auto parse_membership_path(FederationEndpoint endpoint, std::string_view target)
    -> std::optional<MembershipPathParams>;

// Templates returned by the make_join / make_leave / make_knock endpoints.
// The remote peer signs this template, sets `origin_server_ts`, and submits
// it through send_join / send_leave / send_knock.
struct MembershipEventTemplate final
{
    std::string room_id{};
    std::string user_id{};
    std::string membership{};        // "join" | "leave" | "knock"
    std::string room_version{};      // actual room version read from m.room.create
    std::vector<std::string> prev_events{};
    std::vector<std::string> auth_events{};
    std::int64_t depth{0};
    std::string content_json{};      // canonical JSON object for content
    std::string reason{};            // human-readable when an error occurred
};

// Hook signature for building a membership event template. Implementations
// query the persistent store for room state and produce a partial event
// matching the Matrix make_join / make_leave / make_knock spec.
using MembershipTemplateProvider = std::function<std::optional<MembershipEventTemplate>(
    FederationEndpoint endpoint, std::string_view room_id, std::string_view user_id,
    std::vector<std::string> const& supported_room_versions)>;

// Result of accepting a signed membership event through send_join /
// send_leave / send_knock. On success the room's auth chain and current
// state are returned to the remote peer.
struct MembershipAcceptResult final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
    // For send_join: the auth events + state events the remote needs to
    // hydrate the room locally. Empty for send_leave and send_knock.
    std::vector<std::string> auth_chain_json{};
    std::vector<std::string> state_json{};
    // Room version string echoed in the send_join/send_leave response body.
    // Read from m.room.create; empty means the caller should use a safe default.
    std::string room_version{};
    // For send_join v2: the signed join event echoed back in the 'event' field.
    // Per Matrix federation spec §11.5.1 the resident server MUST return the
    // event exactly as it was accepted. Empty for send_leave and send_knock.
    std::string signed_event_json{};
};

// Hook signature for accepting a signed membership event. The implementation
// runs auth-rules, persists the event, and returns the auth chain + state
// snapshot expected by the corresponding send_* response.
using MembershipAcceptor =
    std::function<MembershipAcceptResult(FederationEndpoint endpoint, std::string_view room_id,
                                         std::string_view event_id, InboundPduEnvelope const& envelope)>;

struct InviteRequest final
{
    std::string room_id{};
    std::string event_id{};
    std::string room_version{};
    std::string invite_event_json{};
    std::vector<std::string> invite_room_state_json{};
};

struct InviteAcceptResult final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
    // The signed invite event to return to the inviter. Production
    // implementations sign the event with the local server's signing key;
    // tests can echo the input.
    std::string signed_event_json{};
};

using InviteHandler = std::function<InviteAcceptResult(InviteRequest const&)>;

struct BackfillRequest final
{
    std::string room_id{};
    std::vector<std::string> event_ids{};
    std::size_t limit{0U};
};

struct BackfillResult final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
    std::vector<std::string> pdus_json{};
};

using BackfillProvider = std::function<BackfillResult(BackfillRequest const&)>;

// Parses the v1 backfill query string (?v=eventId&v=eventId&limit=N). Returns
// nullopt when the input is malformed (e.g. limit not numeric).
[[nodiscard]] auto parse_backfill_query(std::string_view target) -> std::optional<BackfillRequest>;

[[nodiscard]] auto parse_invite_body(std::string_view body, std::string_view room_id, std::string_view event_id,
                                     FederationEndpoint endpoint) -> std::optional<InviteRequest>;

} // namespace merovingian::federation
