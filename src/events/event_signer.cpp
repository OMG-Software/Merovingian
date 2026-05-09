// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/events/event_signer.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <variant>

namespace merovingian::events
{
namespace
{

[[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
    -> canonicaljson::ObjectMember const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return &member;
        }
    }

    return nullptr;
}

[[nodiscard]] auto object_member_value(canonicaljson::Object const& object, std::string_view key) noexcept
    -> canonicaljson::Value const*
{
    auto const* member = object_member(object, key);
    return member == nullptr ? nullptr : member->value.get();
}

[[nodiscard]] auto clone_without_unsigned_and_signatures(canonicaljson::Object const& object) -> canonicaljson::Object
{
    auto stripped = canonicaljson::Object{};
    stripped.reserve(object.size());
    for (auto const& member : object)
    {
        if (member.key != "unsigned" && member.key != "signatures")
        {
            stripped.push_back(canonicaljson::make_member(member.key, *member.value));
        }
    }
    return stripped;
}

[[nodiscard]] auto contains_no_control_or_space(std::string_view value) noexcept -> bool
{
    for (auto const character : value)
    {
        auto const byte = static_cast<unsigned char>(character);
        if (byte <= 0x20U || byte == 0x7FU)
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] auto signature_is_valid_shape(std::string_view signature) noexcept -> bool
{
    return !signature.empty() && signature.size() <= 4096U && contains_no_control_or_space(signature);
}

} // namespace

auto signing_key_id_is_valid(SigningKeyId const& key_id) noexcept -> bool
{
    return !key_id.server_name.empty() && !key_id.key_id.empty() && contains_no_control_or_space(key_id.server_name)
        && contains_no_control_or_space(key_id.key_id);
}

auto make_event_signing_payload(canonicaljson::Value const& event) -> canonicaljson::SerializeResult
{
    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    if (object == nullptr)
    {
        return {{}, canonicaljson::CanonicalJsonError::invalid_string};
    }

    return canonicaljson::serialize_canonical(canonicaljson::Value{clone_without_unsigned_and_signatures(*object)});
}

auto attach_event_signature(
    canonicaljson::Value const& event,
    SigningKeyId const& key_id,
    std::string_view signature
) -> canonicaljson::SerializeResult
{
    if (!signing_key_id_is_valid(key_id) || !signature_is_valid_shape(signature))
    {
        return {{}, canonicaljson::CanonicalJsonError::invalid_string};
    }

    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    if (object == nullptr)
    {
        return {{}, canonicaljson::CanonicalJsonError::invalid_string};
    }

    auto signed_object = canonicaljson::Object{};
    signed_object.reserve(object->size() + 1U);
    for (auto const& member : *object)
    {
        if (member.key != "signatures")
        {
            signed_object.push_back(canonicaljson::make_member(member.key, *member.value));
        }
    }

    auto server_signatures = canonicaljson::Object{};
    server_signatures.push_back(canonicaljson::make_member(key_id.key_id, canonicaljson::Value{std::string{signature}}));

    auto signatures = canonicaljson::Object{};
    signatures.push_back(canonicaljson::make_member(key_id.server_name, canonicaljson::Value{std::move(server_signatures)}));
    signed_object.push_back(canonicaljson::make_member("signatures", canonicaljson::Value{std::move(signatures)}));

    return canonicaljson::serialize_canonical(canonicaljson::Value{std::move(signed_object)});
}

auto verify_event_signature_presence(canonicaljson::Value const& event, SigningKeyId const& key_id)
    -> SignatureVerificationResult
{
    if (!signing_key_id_is_valid(key_id))
    {
        return {false, "invalid signing key id"};
    }

    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    if (object == nullptr)
    {
        return {false, "event must be an object"};
    }

    auto const* signatures_value = object_member_value(*object, "signatures");
    if (signatures_value == nullptr)
    {
        return {false, "missing signatures"};
    }
    auto const* signatures = std::get_if<canonicaljson::Object>(&signatures_value->storage());
    if (signatures == nullptr)
    {
        return {false, "signatures must be an object"};
    }

    auto const* server_value = object_member_value(*signatures, key_id.server_name);
    if (server_value == nullptr)
    {
        return {false, "missing server signature"};
    }
    auto const* server_signatures = std::get_if<canonicaljson::Object>(&server_value->storage());
    if (server_signatures == nullptr)
    {
        return {false, "server signatures must be an object"};
    }

    auto const* signature_value = object_member_value(*server_signatures, key_id.key_id);
    if (signature_value == nullptr)
    {
        return {false, "missing key signature"};
    }
    auto const* signature = std::get_if<std::string>(&signature_value->storage());
    if (signature == nullptr || !signature_is_valid_shape(*signature))
    {
        return {false, "invalid signature"};
    }

    return {true, {}};
}

} // namespace merovingian::events
