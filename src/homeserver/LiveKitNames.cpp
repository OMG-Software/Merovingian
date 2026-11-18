// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/LiveKitNames.hpp"

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/Sha256.hpp"

#include <string>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto hash_pair(std::string_view first, std::string_view second) -> std::optional<std::string>
    {
        if (!canonicaljson::string_is_valid_for_json(first) || !canonicaljson::string_is_valid_for_json(second))
        {
            return std::nullopt;
        }
        auto const pair = canonicaljson::Value{
            canonicaljson::Array{canonicaljson::Value{std::string{first}}, canonicaljson::Value{std::string{second}}}
        };
        auto const serialized = canonicaljson::serialize_canonical_strict(pair);
        if (serialized.error != canonicaljson::CanonicalJsonError::none)
        {
            return std::nullopt;
        }
        auto const digest = crypto::sha256(serialized.output);
        if (!digest)
        {
            return std::nullopt;
        }
        auto encoded = crypto::base64_original_encode(*digest);
        if (!encoded)
        {
            return std::nullopt;
        }
        // 32 bytes encode to 44 characters, the last of them one `=`; MSC4195 drops the padding.
        while (!encoded->empty() && encoded->back() == '=')
        {
            encoded->pop_back();
        }
        return encoded;
    }

} // namespace

auto livekit_room_name(std::string_view const room_id, std::string_view const slot_id) -> std::optional<std::string>
{
    return hash_pair(room_id, slot_id == legacy_call_slot_id ? call_slot_id : slot_id);
}

auto livekit_participant_identity(std::string_view const user_id, std::string_view const member_id)
    -> std::optional<std::string>
{
    return hash_pair(user_id, member_id);
}

} // namespace merovingian::homeserver
