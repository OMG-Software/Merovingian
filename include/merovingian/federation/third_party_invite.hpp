// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

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

// A checked `signed` object (SignedThirdPartyInvite): `mxid` is a valid user ID, `token` a non-empty string of at most
// 255 bytes, and `signatures` an object of at most 8 servers holding at most 8 string signatures each. Other members
// are kept, because the identity server's signature covers them. `json` is the canonical JSON of the whole object.
struct SignedThirdPartyInvite final
{
    std::string mxid{};
    std::string token{};
    std::string json{};
};

// One `m.room.member` invite to be issued for a third-party invite, as `exchange_third_party_invite` carries it.
struct ThirdPartyInviteExchange final
{
    std::string room_id{};
    // The user who sent the original `m.room.third_party_invite`, and so the sender of the invite to be issued.
    std::string sender{};
    // The invited user (the event's `state_key`).
    std::string target_user_id{};
    SignedThirdPartyInvite signed_invite{};
};

struct ThirdPartyInviteExchangeParse final
{
    std::optional<ThirdPartyInviteExchange> exchange{};
    std::string reason{};
};

// Parses an `exchange_third_party_invite` body. `path_room_id` is the decoded `{roomId}`; the body's `room_id` must
// equal it. The event must be an `m.room.member` with `membership: invite` and a `third_party_invite` holding a valid
// `signed`. `display_name` is not required (servers in practice omit it) and never read: the invite takes its display
// name from the room's own `m.room.third_party_invite` (ADR-0485).
[[nodiscard]] auto parse_third_party_invite_exchange(std::string_view body, std::string_view path_room_id)
    -> ThirdPartyInviteExchangeParse;

// The body this server sends to the inviting server's `exchange_third_party_invite`.
[[nodiscard]] auto build_third_party_invite_exchange_body(ThirdPartyInviteExchange const& exchange) -> std::string;

// One entry of a `/3pid/onbind` notification, checked.
struct ThirdPartyBindInvite final
{
    std::string address{};
    std::string medium{};
    std::string room_id{};
    std::string sender{};
    SignedThirdPartyInvite signed_invite{};
};

struct ThirdPartyBindNotification final
{
    std::string address{};
    std::string medium{};
    // The user the third-party identifier is now bound to.
    std::string mxid{};
    // Only the entries that are well formed and name `mxid`; `dropped` counts the others, which are not acted on.
    std::vector<ThirdPartyBindInvite> invites{};
    std::size_t dropped{0U};
};

struct ThirdPartyBindParse final
{
    std::optional<ThirdPartyBindNotification> notification{};
    std::string reason{};
};

// Parses a `/3pid/onbind` body. A body that is not an object with a string `address` and `medium`, a valid `mxid` and
// an `invites` array of at most `max_third_party_bind_invites` entries is refused whole; an entry that is malformed or
// names another user than `mxid` is dropped alone.
[[nodiscard]] auto parse_third_party_bind_notification(std::string_view body) -> ThirdPartyBindParse;

// How a server's exchange of a third-party invite ended.
struct ThirdPartyInviteExchangeResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string reason{};
};

// Issues the invite, in the process that signs for this server (main). `origin` is the X-Matrix-authenticated caller.
// Unset in a federation worker, which has no signing key: the endpoint is then answered 501.
using ThirdPartyInviteExchanger =
    std::function<ThirdPartyInviteExchangeResult(ThirdPartyInviteExchange const&, std::string const& origin)>;

} // namespace merovingian::federation
