// SPDX-FileCopyrightText: 2026 James Chapman
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
    std::string reason{};       // human-readable when an error occurred
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
    // For send_knock: stripped room state events shown to the knocking user
    // while waiting for the knock to be answered. Spec MUST be present in
    // the send_knock response body under the "knock_room_state" key.
    std::vector<std::string> knock_room_state_json{};
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
    // The X-Matrix-authenticated origin of the requesting server. The invite
    // handler asserts that the event sender's server name matches this origin
    // (spec §4223: "the event sender is not a user ID on the origin server").
    std::string origin{};
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
    // The X-Matrix-authenticated origin of the requesting server, filled in by
    // the inbound handler (never parsed from the request). The provider uses it
    // to refuse a server that has no joined user in the room (FED-2).
    std::string origin{};
};

struct BackfillResult final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
    std::vector<std::string> pdus_json{};
};

using BackfillProvider = std::function<BackfillResult(BackfillRequest const&)>;

// Per-requested-event-graph work limits for federation history endpoints.
// These are operator policies, not protocol maxima. Matrix gives backfill a
// requested count and get_missing_events an optional count (default 10), but
// does not require a server to honour an arbitrarily large requested count.
struct FederationQueryPolicy final
{
    std::size_t max_backfill_pdus{500U};
    std::size_t max_missing_events_pdus{100U};
    std::size_t max_missing_events_latest{100U};
    std::size_t max_missing_events_traversal{4096U};
};

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
