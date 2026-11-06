// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/third_party_invite.hpp"

#include "merovingian/auth/identity.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/event.hpp"

#include <algorithm>
#include <cstddef>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::federation
{
namespace
{

    constexpr auto max_signature_servers = std::size_t{8U};
    constexpr auto max_signatures_per_server = std::size_t{8U};
    constexpr auto max_signature_bytes = std::size_t{128U};
    constexpr auto max_token_bytes = std::size_t{255U};
    constexpr auto max_identifier_bytes = std::size_t{255U};

    [[nodiscard]] auto find_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_of(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = find_member(object, key);
        return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto object_of(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = find_member(object, key);
        return value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto text_is_bounded(std::string const& text, std::size_t limit) noexcept -> bool
    {
        return !text.empty() && text.size() <= limit && text.find('\0') == std::string::npos;
    }

    [[nodiscard]] auto signatures_are_bounded(canonicaljson::Object const& signatures) noexcept -> bool
    {
        if (signatures.empty() || signatures.size() > max_signature_servers)
        {
            return false;
        }
        return std::ranges::all_of(signatures, [](auto const& server) {
            auto const* keys = std::get_if<canonicaljson::Object>(&server.value->storage());
            if (keys == nullptr || keys->empty() || keys->size() > max_signatures_per_server)
            {
                return false;
            }
            return std::ranges::all_of(*keys, [](auto const& entry) {
                auto const* signature = std::get_if<std::string>(&entry.value->storage());
                return signature != nullptr && !signature->empty() && signature->size() <= max_signature_bytes;
            });
        });
    }

} // namespace

namespace
{

    [[nodiscard]] auto parse_signed(canonicaljson::Value const& value) -> std::optional<SignedThirdPartyInvite>
    {
        auto const* object = std::get_if<canonicaljson::Object>(&value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto const* mxid = string_of(*object, "mxid");
        auto const* token = string_of(*object, "token");
        auto const* signatures = object_of(*object, "signatures");
        if (mxid == nullptr || token == nullptr || signatures == nullptr || !auth::user_id_is_valid_federated(*mxid) ||
            !text_is_bounded(*token, max_token_bytes) || !signatures_are_bounded(*signatures))
        {
            return std::nullopt;
        }
        auto const serialized = canonicaljson::serialize_canonical(value);
        if (serialized.error != canonicaljson::CanonicalJsonError::none ||
            serialized.output.size() > max_signed_third_party_invite_bytes)
        {
            return std::nullopt;
        }
        return SignedThirdPartyInvite{*mxid, *token, serialized.output};
    }

    [[nodiscard]] auto valid_room_id(std::string const& room_id) noexcept -> bool
    {
        return room_id.size() <= max_identifier_bytes && events::matrix_id_is_valid(room_id, '!');
    }

} // namespace

auto parse_third_party_invite_exchange(std::string_view body, std::string_view path_room_id)
    -> ThirdPartyInviteExchangeParse
{
    auto const refused = [](std::string reason) {
        return ThirdPartyInviteExchangeParse{std::nullopt, std::move(reason)};
    };
    auto const parsed = canonicaljson::parse_json(body);
    auto const* root = parsed.error == canonicaljson::ParseError::none
                           ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                           : nullptr;
    if (root == nullptr)
    {
        return refused("body is not a JSON object");
    }
    auto const* type = string_of(*root, "type");
    if (type == nullptr || *type != "m.room.member")
    {
        return refused("type must be m.room.member");
    }
    auto const* room_id = string_of(*root, "room_id");
    if (room_id == nullptr || !valid_room_id(*room_id) || *room_id != path_room_id)
    {
        return refused("room_id must be a room ID equal to the one in the path");
    }
    auto const* sender = string_of(*root, "sender");
    if (sender == nullptr || !auth::user_id_is_valid_federated(*sender))
    {
        return refused("sender must be a user ID");
    }
    auto const* state_key = string_of(*root, "state_key");
    if (state_key == nullptr || !auth::user_id_is_valid_federated(*state_key))
    {
        return refused("state_key must be a user ID");
    }
    auto const* content = object_of(*root, "content");
    auto const* membership = content == nullptr ? nullptr : string_of(*content, "membership");
    if (membership == nullptr || *membership != "invite")
    {
        return refused("content.membership must be invite");
    }
    auto const* third_party_invite = object_of(*content, "third_party_invite");
    auto const* signed_value = third_party_invite == nullptr ? nullptr : find_member(*third_party_invite, "signed");
    if (signed_value == nullptr)
    {
        return refused("content.third_party_invite.signed is required");
    }
    auto signed_invite = parse_signed(*signed_value);
    if (!signed_invite.has_value())
    {
        return refused("content.third_party_invite.signed is malformed");
    }
    return {
        ThirdPartyInviteExchange{*room_id, *sender, *state_key, std::move(*signed_invite)},
        {}
    };
}

auto build_third_party_invite_exchange_body(ThirdPartyInviteExchange const& exchange) -> std::string
{
    auto const signed_value = canonicaljson::parse_json(exchange.signed_invite.json);
    if (signed_value.error != canonicaljson::ParseError::none)
    {
        return {};
    }
    auto invite = canonicaljson::Object{};
    // `display_name` is Required by the spec. `3pid/onbind` supplies none, so it is empty: that satisfies the schema,
    // invents nothing and discloses nothing; the inviting server takes the real name from its own event (ADR-0485).
    invite.push_back(canonicaljson::make_member("display_name", canonicaljson::Value{std::string{}}));
    invite.push_back(canonicaljson::make_member("signed", signed_value.value));
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"invite"}}));
    content.push_back(canonicaljson::make_member("third_party_invite", canonicaljson::Value{std::move(invite)}));
    auto event = canonicaljson::Object{};
    event.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{exchange.room_id}));
    event.push_back(canonicaljson::make_member("sender", canonicaljson::Value{exchange.sender}));
    event.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{exchange.target_user_id}));
    event.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.member"}}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(event)});
    return serialized.error == canonicaljson::CanonicalJsonError::none ? serialized.output : std::string{};
}

auto parse_third_party_bind_notification(std::string_view body) -> ThirdPartyBindParse
{
    auto const refused = [](std::string reason) {
        return ThirdPartyBindParse{std::nullopt, std::move(reason)};
    };
    auto const parsed = canonicaljson::parse_json(body);
    auto const* root = parsed.error == canonicaljson::ParseError::none
                           ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                           : nullptr;
    if (root == nullptr)
    {
        return refused("body is not a JSON object");
    }
    auto const* address = string_of(*root, "address");
    auto const* medium = string_of(*root, "medium");
    auto const* mxid = string_of(*root, "mxid");
    auto const* invites_value = find_member(*root, "invites");
    auto const* invites =
        invites_value == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&invites_value->storage());
    if (address == nullptr || !text_is_bounded(*address, max_identifier_bytes) || medium == nullptr ||
        !text_is_bounded(*medium, max_identifier_bytes) || mxid == nullptr ||
        !auth::user_id_is_valid_federated(*mxid) || invites == nullptr)
    {
        return refused("address, medium, mxid and invites are required");
    }
    auto notification = ThirdPartyBindNotification{*address, *medium, *mxid, {}, 0U};
    // Only the first `max_third_party_bind_invites` are looked at; the spec gives no status for more, and refusing the
    // body would lose every invite the identity server holds for this user. The rest are counted, not read.
    if (invites->size() > max_third_party_bind_invites)
    {
        notification.dropped = invites->size() - max_third_party_bind_invites;
    }
    for (auto const& entry : *invites | std::views::take(max_third_party_bind_invites))
    {
        auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
        auto const* entry_address = object == nullptr ? nullptr : string_of(*object, "address");
        auto const* entry_medium = object == nullptr ? nullptr : string_of(*object, "medium");
        auto const* entry_mxid = object == nullptr ? nullptr : string_of(*object, "mxid");
        auto const* entry_room = object == nullptr ? nullptr : string_of(*object, "room_id");
        auto const* entry_sender = object == nullptr ? nullptr : string_of(*object, "sender");
        auto const* entry_signed = object == nullptr ? nullptr : find_member(*object, "signed");
        auto signed_invite = entry_signed == nullptr ? std::nullopt : parse_signed(*entry_signed);
        if (entry_address == nullptr || !text_is_bounded(*entry_address, max_identifier_bytes) ||
            entry_medium == nullptr || !text_is_bounded(*entry_medium, max_identifier_bytes) || entry_mxid == nullptr ||
            *entry_mxid != *mxid || entry_room == nullptr || !valid_room_id(*entry_room) || entry_sender == nullptr ||
            !auth::user_id_is_valid_federated(*entry_sender) || !signed_invite.has_value() ||
            signed_invite->mxid != *mxid)
        {
            ++notification.dropped;
            continue;
        }
        notification.invites.push_back(
            ThirdPartyBindInvite{*entry_address, *entry_medium, *entry_room, *entry_sender, std::move(*signed_invite)});
    }
    return {std::move(notification), {}};
}

} // namespace merovingian::federation
