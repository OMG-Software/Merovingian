// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/event_signer.hpp"

#include "merovingian/events/redaction.hpp"

#include <string>
#include <string_view>
#include <variant>

#include <sodium.h>

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

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
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
        auto const decoded = matrix_bytes_from_base64(signature);
        return !signature.empty() && signature.size() <= 4096U && contains_no_control_or_space(signature) &&
               crypto::ed25519_signature_shape_is_valid(crypto::Ed25519Signature{decoded});
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

auto matrix_base64_from_bytes(std::string_view bytes) -> std::string
{
    if (bytes.empty() || !sodium_is_ready())
    {
        return {};
    }

    auto output = std::string(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL_NO_PADDING), '\0');
    static_cast<void>(sodium_bin2base64(output.data(), output.size(),
                                        reinterpret_cast<unsigned char const*>(bytes.data()), bytes.size(),
                                        sodium_base64_VARIANT_ORIGINAL_NO_PADDING));
    output.resize(std::char_traits<char>::length(output.c_str()));
    return output;
}

auto matrix_bytes_from_base64(std::string_view encoded) -> std::string
{
    if (encoded.empty() || !sodium_is_ready())
    {
        return {};
    }

    auto output = std::string((encoded.size() * 3U) / 4U + 3U, '\0');
    auto decoded_length = std::size_t{0U};
    if (sodium_base642bin(reinterpret_cast<unsigned char*>(output.data()), output.size(), encoded.data(),
                          encoded.size(), nullptr, &decoded_length, nullptr,
                          sodium_base64_VARIANT_ORIGINAL_NO_PADDING) != 0)
    {
        return {};
    }

    output.resize(decoded_length);
    return output;
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

auto make_event_signing_payload(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy)
    -> canonicaljson::SerializeResult
{
    auto redacted = redact_event(event, policy);
    if (!redacted.error.empty())
    {
        return {{}, canonicaljson::CanonicalJsonError::invalid_string};
    }

    return make_event_signing_payload(redacted.event);
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

auto sign_event_for_server(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy,
                           crypto::SigningKeyStore& key_store, crypto::Ed25519Provider& provider,
                           std::string_view server_name) -> SignedEventResult
{
    auto const payload = make_event_signing_payload(event, policy);
    if (payload.error != canonicaljson::CanonicalJsonError::none)
    {
        return {{}, {}, {}, {}, canonicaljson::canonical_json_error_name(payload.error)};
    }

    auto signature = crypto::sign_for_server(key_store, provider, server_name, payload.output);
    if (!signature.error.empty())
    {
        return {{}, signature.server_name, signature.key_id, {}, signature.error};
    }

    auto const encoded = matrix_base64_from_bytes(signature.signature.bytes);
    if (encoded.empty())
    {
        return {{}, signature.server_name, signature.key_id, {}, "signature base64 encoding failed"};
    }

    auto signed_json = attach_event_signature(event, {signature.server_name, signature.key_id}, encoded);
    if (signed_json.error != canonicaljson::CanonicalJsonError::none)
    {
        return {{},
                signature.server_name,
                signature.key_id,
                encoded,
                canonicaljson::canonical_json_error_name(signed_json.error)};
    }

    return {signed_json.output, signature.server_name, signature.key_id, encoded, {}};
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

auto verify_event_signature(canonicaljson::Value const& event, rooms::RoomVersionPolicy const& policy,
                            SigningKeyId const& key_id, crypto::Ed25519PublicKey const& public_key,
                            crypto::Ed25519Provider& provider) -> SignatureVerificationResult
{
    auto presence = verify_event_signature_presence(event, key_id);
    if (!presence.valid)
    {
        return presence;
    }

    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    auto const* signatures_value = object == nullptr ? nullptr : object_member_value(*object, "signatures");
    auto const* signatures =
        signatures_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&signatures_value->storage());
    auto const* server_value = signatures == nullptr ? nullptr : object_member_value(*signatures, key_id.server_name);
    auto const* server_signatures =
        server_value == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&server_value->storage());
    auto const* signature_value =
        server_signatures == nullptr ? nullptr : object_member_value(*server_signatures, key_id.key_id);
    auto const* encoded_signature =
        signature_value == nullptr ? nullptr : std::get_if<std::string>(&signature_value->storage());
    if (encoded_signature == nullptr)
    {
        return {false, "missing key signature"};
    }

    auto const signature_bytes = matrix_bytes_from_base64(*encoded_signature);
    if (!crypto::ed25519_signature_shape_is_valid(crypto::Ed25519Signature{signature_bytes}))
    {
        return {false, "invalid signature"};
    }

    auto payload = make_event_signing_payload(event, policy);
    if (payload.error != canonicaljson::CanonicalJsonError::none)
    {
        return {false, canonicaljson::canonical_json_error_name(payload.error)};
    }

    auto verified = provider.verify(public_key, payload.output, crypto::Ed25519Signature{signature_bytes});
    return verified.valid ? SignatureVerificationResult{true, {}} : SignatureVerificationResult{false, verified.error};
}

} // namespace merovingian::events
