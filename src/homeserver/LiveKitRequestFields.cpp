// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/LiveKitRequestFields.hpp"

#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/homeserver/LiveKitTokenRequest.hpp"
#include "merovingian/homeserver/LiveKitTokenService.hpp"

#include <utility>
#include <variant>

namespace merovingian::homeserver
{

auto livekit_refusal(std::uint16_t const status, std::string errcode, std::string reason) -> OperationResult
{
    auto result = OperationResult{};
    result.ok = false;
    result.status = status;
    result.errcode = std::move(errcode);
    result.reason = std::move(reason);
    return result;
}

auto livekit_member_of(canonicaljson::Object const& object, std::string_view const key) -> canonicaljson::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key && member.value != nullptr)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

auto read_livekit_string(canonicaljson::Object const& object, std::string_view const key, std::size_t const max_bytes,
                         std::string& out) -> std::optional<OperationResult>
{
    auto const* value = livekit_member_of(object, key);
    if (value == nullptr)
    {
        return livekit_refusal(400U, "M_MISSING_PARAM", std::string{key} + " is required");
    }
    auto const* text = std::get_if<std::string>(&value->storage());
    if (text == nullptr || text->empty() || text->size() > max_bytes || !canonicaljson::string_is_valid_for_json(*text))
    {
        return livekit_refusal(400U, "M_INVALID_PARAM", std::string{key} + " is not valid");
    }
    out = *text;
    return std::nullopt;
}

auto read_livekit_call_members(canonicaljson::Object const& object, LiveKitTokenRequest& request)
    -> std::optional<OperationResult>
{
    if (auto refused = read_livekit_string(object, "url", max_livekit_url_bytes, request.url))
    {
        return refused;
    }
    if (auto refused = read_livekit_string(object, "room_id", max_livekit_room_id_bytes, request.room_id))
    {
        return refused;
    }
    if (!request.room_id.starts_with('!'))
    {
        return livekit_refusal(400U, "M_INVALID_PARAM", "room_id is not valid");
    }
    if (auto refused = read_livekit_string(object, "slot_id", max_livekit_slot_id_bytes, request.slot_id))
    {
        return refused;
    }
    return read_livekit_string(object, "member_id", max_livekit_member_id_bytes, request.member_id);
}

} // namespace merovingian::homeserver
