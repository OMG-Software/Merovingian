// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/event_signer.hpp"

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

    [[nodiscard]] auto clone_without_unsigned_and_signatures(canonicaljson::Object const& object)
        -> canonicaljson::Object
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

    [[nodiscard]] auto clone_signature_object(canonicaljson::Value const* signatures_value) -> canonicaljson::Object
    {
        if (signatures_value == nullptr)
        {
            return {};
        }

        auto const* signatures = std::get_if<canonicaljson::Object>(&signatures_value->storage());
        if (signatures == nullptr)
        {
            return {};
        }

        auto cloned = canonicaljson::Object{};
        cloned.reserve(signatures->size());
        for (auto const& member : *signatures)
        {
            cloned.push_back(canonicaljson::make_member(member.key, *member.value));
        }
        return cloned;
    }

    [[nodiscard]] auto clone_server_signatures(canonicaljson::Value const& server_value) -> canonicaljson::Object
    {
        auto const* existing = std::get_if<canonicaljson::Object>(&server_value.storage());
        if (existing == nullptr)
        {
            return {};
        }

        auto cloned = canonicaljson::Object{};
        cloned.reserve(existing->size());
        for (auto const& member : *existing)
        {
            cloned.push_back(canonicaljson::make_member(member.key, *member.value));
        }
        return cloned;
    }

    auto upsert_server_signature(canonicaljson::Object& server_signatures, SigningKeyId const& key_id,
                                 std::string_view signature) -> void
    {
        for (auto& key_member : server_signatures)
        {
            if (key_member.key == key_id.key_id)
            {
                key_member.value = std::make_unique<canonicaljson::Value>(std::string{signature});
                return;
            }
        }

        server_signatures.push_back(
            canonicaljson::make_member(key_id.key_id, canonicaljson::Value{std::string{signature}}));
    }

    auto upsert_signature(canonicaljson::Object& signatures, SigningKeyId const& key_id, std::string_view signature)
        -> void
    {
        for (auto& server_member : signatures)
        {
            if (server_member.key == key_id.server_name)
            {
                auto server_signatures = clone_server_signatures(*server_member.value);
                upsert_server_signature(server_signatures, key_id, signature);
                server_member.value = std::make_unique<canonicaljson::Value>(std::move(server_signatures));
                return;
            }
        }

        auto server_signatures = canonicaljson::Object{};
        server_signatures.push_back(
            canonicaljson::make_member(key_id.key_id, canonicaljson::Value{std::string{signature}}));
        signatures.push_back(
            canonicaljson::make_member(key_id.server_name, canonicaljson::Value{std::move(server_signatures)}));
    }

} // namespace

auto signing_key_id_is_valid(SigningKeyId const& key_id) noexcept -> bool
{
    return !key_id.server_name.empty() && !key_id.key_id.empty() && contains_no_control_or_space(key_id.server_name) &&
           contains_no_control_or_space(key_id.key_id);
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

auto attach_event_signature(canonicaljson::Value const& event, SigningKeyId const& key_id, std::string_view signature)
    -> canonicaljson::SerializeResult
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
    auto const* signatures_value = object_member_value(*object, "signatures");
    for (auto const& member : *object)
    {
        if (member.key != "signatures")
        {
            signed_object.push_back(canonicaljson::make_member(member.key, *member.value));
        }
    }

    auto signatures = clone_signature_object(signatures_value);
    upsert_signature(signatures, key_id, signature);
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
    auto const* found_signature = std::get_if<std::string>(&signature_value->storage());
    if (found_signature == nullptr || !signature_is_valid_shape(*found_signature))
    {
        return {false, "invalid signature"};
    }

    return {true, {}};
}

} // namespace merovingian::events
