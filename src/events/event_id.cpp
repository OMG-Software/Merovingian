// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/event_id.hpp"

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/events/redaction.hpp"

#include <algorithm>
#include <array>
#include <initializer_list>
#include <string>
#include <string_view>
#include <variant>

#include <sodium.h>

namespace merovingian::events
{
namespace
{

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    [[nodiscard]] auto matrix_base64_from_digest(std::array<unsigned char, crypto_hash_sha256_BYTES> const& digest,
                                                 bool url_safe) -> std::string
    {
        auto output =
            std::string(sodium_base64_ENCODED_LEN(digest.size(), sodium_base64_VARIANT_ORIGINAL_NO_PADDING), '\0');
        auto const variant =
            url_safe ? sodium_base64_VARIANT_URLSAFE_NO_PADDING : sodium_base64_VARIANT_ORIGINAL_NO_PADDING;
        static_cast<void>(sodium_bin2base64(output.data(), output.size(), digest.data(), digest.size(), variant));
        output.resize(std::char_traits<char>::length(output.c_str()));
        return output;
    }

    [[nodiscard]] auto sha256_base64(std::string_view input, bool url_safe) -> EventHashResult
    {
        if (!sodium_is_ready())
        {
            return {{}, "libsodium initialization failed"};
        }

        auto digest = std::array<unsigned char, crypto_hash_sha256_BYTES>{};
        if (crypto_hash_sha256(digest.data(), reinterpret_cast<unsigned char const*>(input.data()), input.size()) != 0)
        {
            return {{}, "sha256 failed"};
        }

        return {matrix_base64_from_digest(digest, url_safe), {}};
    }

    [[nodiscard]] auto clone_without_fields(canonicaljson::Object const& object,
                                            std::initializer_list<std::string_view> fields) -> canonicaljson::Object
    {
        auto stripped = canonicaljson::Object{};
        stripped.reserve(object.size());
        for (auto const& member : object)
        {
            auto const excluded = std::ranges::any_of(fields, [&member](std::string_view field) {
                return member.key == field;
            });
            if (!excluded)
            {
                stripped.push_back(canonicaljson::make_member(member.key, *member.value));
            }
        }
        return stripped;
    }

    [[nodiscard]] auto serialize_object_without(canonicaljson::Value const& event,
                                                std::initializer_list<std::string_view> fields)
        -> canonicaljson::SerializeResult
    {
        auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
        if (object == nullptr)
        {
            return {{}, canonicaljson::CanonicalJsonError::invalid_string};
        }

        return canonicaljson::serialize_canonical(canonicaljson::Value{clone_without_fields(*object, fields)});
    }

} // namespace

auto event_id_is_valid(std::string_view event_id) noexcept -> bool
{
    if (event_id.size() < 3U || event_id.front() != '$')
    {
        return false;
    }

    for (auto const character : event_id.substr(1U))
    {
        auto const valid = (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
                           (character >= '0' && character <= '9') || character == '_' || character == '-' ||
                           character == ':' || character == '.';
        if (!valid)
        {
            return false;
        }
    }

    return true;
}

auto make_content_hash_id(canonicaljson::Value const& event) -> EventIdResult
{
    auto const* policy = rooms::find_room_version_policy("12");
    return policy == nullptr ? EventIdResult{{}, "room version policy not found"}
                             : make_reference_hash_event_id(event, *policy);
}

auto make_content_hash(canonicaljson::Value const& event) -> EventHashResult
{
    auto const serialized = serialize_object_without(event, {"unsigned", "signatures", "hashes"});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return {{}, canonicaljson::canonical_json_error_name(serialized.error)};
    }

    return sha256_base64(serialized.output, false);
}

auto make_reference_hash(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy) -> EventHashResult
{
    auto redacted = redact_event(event, policy);
    if (!redacted.error.empty())
    {
        return {{}, redacted.error};
    }

    auto const serialized = serialize_object_without(redacted.event, {"signatures", "unsigned"});
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return {{}, canonicaljson::canonical_json_error_name(serialized.error)};
    }

    return sha256_base64(serialized.output, true);
}

auto make_reference_hash_event_id(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> EventIdResult
{
    auto const hash = make_reference_hash(event, policy);
    if (!hash.error.empty())
    {
        return {{}, hash.error};
    }

    return {"$" + hash.sha256, {}};
}

} // namespace merovingian::events
