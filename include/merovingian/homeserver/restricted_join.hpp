// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/RestrictedJoinDecision.hpp" // split-shim
#include "merovingian/homeserver/RestrictedJoinVerdict.hpp"  // split-shim
#include "merovingian/homeserver/RestrictedJoinWork.hpp"     // split-shim

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{
struct PersistentStore;
} // namespace merovingian::database

namespace merovingian::homeserver
{

// The number of allow conditions in m.room.join_rules that are considered.
// The list is room state another server's administrator can write, and each
// condition costs a lookup in this server's state under runtime.mutex, so it
// is bounded; a condition past the bound is treated as absent (fail closed).
// ADR-0185.
inline constexpr std::size_t max_restricted_join_conditions{32U};

// Decides a join of `user_id` into `room_id` from this server's current state
// (`our_server` is this server's name). `named_authoriser`, when not empty, is
// the join_authorised_via_users_server a submitted join already names (the
// send_join path): only that user is considered, and it must be a user of
// this server. When empty (make_join, or a local join) the authorising user is
// chosen: the lowest user ID among this server's joined users with the invite
// power level. A condition's room can be validated only while this server is
// resident in it (its m.room.create is stored and a user of this server is
// joined): state kept after leaving is not current. No condition met and one
// that cannot be validated is unable_to_authorise; all validated and none met
// is forbidden. Reads only; the caller holds runtime.mutex.
[[nodiscard]] auto decide_restricted_join(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view user_id, std::string_view our_server,
                                          std::string_view named_authoriser = {}) -> RestrictedJoinDecision;

// The most servers a local join tries through the federated join handshake when
// `decide_restricted_join` finds the user meets a condition but no user of this
// server can authorise the join (ADR-0287). Each candidate costs one make_join, so
// the list is bounded however many servers the room has.
inline constexpr std::size_t max_restricted_join_fallback_candidates{4U};

// The servers a local join of a restricted room this server is resident in goes
// through when no local user can authorise it (server-server-api.md "Restricted
// rooms": M_UNABLE_TO_GRANT_JOIN, "the joining server should try a different
// server"): the servers the client named (`via_servers`, in order) first, then
// the other servers with joined members (`resident_servers`). This server is
// never a candidate, a server appears once, and at most `max_candidates` are
// returned.
[[nodiscard]] auto restricted_join_fallback_candidates(std::vector<std::string> const& via_servers,
                                                       std::vector<std::string> const& resident_servers,
                                                       std::string_view our_server, std::size_t max_candidates)
    -> std::vector<std::string>;

// The HTTP status and Matrix errcode for a refusing verdict
// (unable_to_authorise, unable_to_grant, forbidden). Any other verdict is not
// a refusal and maps to 200 / an empty errcode.
[[nodiscard]] auto restricted_join_refusal_status(RestrictedJoinVerdict verdict) noexcept -> std::uint16_t;
[[nodiscard]] auto restricted_join_refusal_errcode(RestrictedJoinVerdict verdict) noexcept -> std::string_view;

} // namespace merovingian::homeserver
