// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/SignedThirdPartyInvite.hpp"         // split-shim
#include "merovingian/federation/ThirdPartyBindInvite.hpp"           // split-shim
#include "merovingian/federation/ThirdPartyBindNotification.hpp"     // split-shim
#include "merovingian/federation/ThirdPartyBindParse.hpp"            // split-shim
#include "merovingian/federation/ThirdPartyInviteExchange.hpp"       // split-shim
#include "merovingian/federation/ThirdPartyInviteExchangeParse.hpp"  // split-shim
#include "merovingian/federation/ThirdPartyInviteExchangeResult.hpp" // split-shim

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Server-Server API v1.19, "Third-party invites": `PUT /_matrix/federation/v1/exchange_third_party_invite/{roomId}` and
// `PUT /_matrix/federation/v1/3pid/onbind`. Everything in both bodies is chosen by the caller, so these parsers refuse
// what is malformed or over a bound before anything is looked up, and hand on only values they have checked.

// The most invites one `/3pid/onbind` request is acted on for. Each valid one costs one exchange, which can mean a
// signed federation request to the inviting server, and the endpoint has no authentication (ADR-0484).
inline constexpr std::size_t max_third_party_bind_invites{32U};

// The most bytes of a `signed` object (canonical JSON) that is looked at. A real one is `mxid`, `token` and a signature
// or two, a few hundred bytes.
inline constexpr std::size_t max_signed_third_party_invite_bytes{4096U};

// Parses an `exchange_third_party_invite` body. `path_room_id` is the decoded `{roomId}`; the body's `room_id` must
// equal it. The event must be an `m.room.member` with `membership: invite` and a `third_party_invite` holding a valid
// `signed`. `display_name` is accepted when absent although the spec marks it Required: it is never read (the invite
// takes its display name from the room's own `m.room.third_party_invite`), so refusing its absence protects nothing.
// That is a tolerance on receipt, not a reading of the spec (ADR-0485).
[[nodiscard]] auto parse_third_party_invite_exchange(std::string_view body, std::string_view path_room_id)
    -> ThirdPartyInviteExchangeParse;

// The body this server sends to the inviting server's `exchange_third_party_invite`.
[[nodiscard]] auto build_third_party_invite_exchange_body(ThirdPartyInviteExchange const& exchange) -> std::string;

// Parses a `/3pid/onbind` body. A body that is not an object with a string `address` and `medium`, a valid `mxid` and
// an `invites` array is refused whole. Only the first `max_third_party_bind_invites` entries are read; the rest are
// counted in `dropped` (the spec gives no status for more), as is an entry that is malformed or names another user than
// `mxid`.
[[nodiscard]] auto parse_third_party_bind_notification(std::string_view body) -> ThirdPartyBindParse;

// Issues the invite, in the process that signs for this server (main). `origin` is the X-Matrix-authenticated caller.
// Unset in a federation worker, which has no signing key: the endpoint is then answered 501.
using ThirdPartyInviteExchanger =
    std::function<ThirdPartyInviteExchangeResult(ThirdPartyInviteExchange const&, std::string const& origin)>;

} // namespace merovingian::federation
