// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

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
    // For send_join v2 (F-23): true when `m.room.member` events were left out of `state_json`
    // because the request set `omit_members`, and then the servers with joined members before the
    // join, which the spec requires with it.
    bool members_omitted{false};
    std::vector<std::string> servers_in_room{};
};

} // namespace merovingian::federation
