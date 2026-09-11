// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/key_signatures.hpp"

#include "merovingian/canonicaljson/parser.hpp"

#include <utility>
#include <variant>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto member_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        for (auto const& member : object)
        {
            if (member.key == key && member.value != nullptr)
            {
                return std::get_if<canonicaljson::Object>(&member.value->storage());
            }
        }
        return nullptr;
    }

    // Replaces `key`'s value in `object`, or appends it when absent.
    auto set_member(canonicaljson::Object& object, std::string_view key, canonicaljson::Value value) -> void
    {
        for (auto& member : object)
        {
            if (member.key == key)
            {
                member = canonicaljson::make_member(std::string{key}, std::move(value));
                return;
            }
        }
        object.push_back(canonicaljson::make_member(std::string{key}, std::move(value)));
    }

    [[nodiscard]] auto parsed_object(std::string_view json) -> std::optional<canonicaljson::Object>
    {
        auto parsed = canonicaljson::parse_lossless(json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        return std::move(*object);
    }

    // The visibility rule (ADR-0060): the owner's own uploads are public;
    // anyone else's upload is shown only to the user who made it.
    [[nodiscard]] auto upload_is_visible(database::PersistentKeySignature const& upload,
                                         std::string_view target_user_id,
                                         std::optional<std::string_view> viewer_user_id) noexcept -> bool
    {
        return upload.signer_user_id == target_user_id ||
               (viewer_user_id.has_value() && upload.signer_user_id == *viewer_user_id);
    }

} // namespace

auto cross_signing_key_id(canonicaljson::Object const& key_object) -> std::optional<std::string>
{
    auto const* keys = member_object(key_object, "keys");
    if (keys == nullptr || keys->size() != 1U)
    {
        return std::nullopt;
    }
    auto const& name = keys->front().key;
    auto const colon = name.find(':');
    if (colon == std::string::npos || colon == 0U || colon + 1U == name.size())
    {
        return std::nullopt;
    }
    return name.substr(colon + 1U);
}

auto merge_visible_key_signatures(canonicaljson::Object& key_object, database::PersistentStore const& store,
                                  std::string_view target_user_id, std::string_view target_key_id,
                                  std::optional<std::string_view> viewer_user_id) -> void
{
    auto signatures = canonicaljson::Object{};
    if (auto const* existing = member_object(key_object, "signatures"); existing != nullptr)
    {
        signatures = *existing;
    }
    auto merged_any = false;
    for (auto const& upload : store.key_signatures)
    {
        if (upload.target_user_id != target_user_id || upload.target_device_id != target_key_id ||
            !upload_is_visible(upload, target_user_id, viewer_user_id))
        {
            continue;
        }
        auto const uploaded = parsed_object(upload.json);
        if (!uploaded.has_value())
        {
            continue;
        }
        // Only the uploader's own signer entry: an upload that also carries
        // an entry under someone else's user ID is not their signature.
        auto const* uploaded_signatures = member_object(*uploaded, "signatures");
        auto const* by_uploader =
            uploaded_signatures == nullptr ? nullptr : member_object(*uploaded_signatures, upload.signer_user_id);
        if (by_uploader == nullptr)
        {
            continue;
        }
        auto signer_signatures = canonicaljson::Object{};
        if (auto const* existing_signer = member_object(signatures, upload.signer_user_id); existing_signer != nullptr)
        {
            signer_signatures = *existing_signer;
        }
        for (auto const& signature : *by_uploader)
        {
            if (signature.value != nullptr && std::holds_alternative<std::string>(signature.value->storage()))
            {
                set_member(signer_signatures, signature.key, *signature.value);
            }
        }
        set_member(signatures, upload.signer_user_id, canonicaljson::Value{std::move(signer_signatures)});
        merged_any = true;
    }
    if (merged_any)
    {
        set_member(key_object, "signatures", canonicaljson::Value{std::move(signatures)});
    }
}

auto published_device_keys(database::PersistentStore const& store, database::PersistentDeviceKey const& device_key,
                           std::optional<std::string_view> viewer_user_id) -> std::optional<canonicaljson::Object>
{
    auto object = parsed_object(device_key.json);
    if (!object.has_value())
    {
        return std::nullopt;
    }
    merge_visible_key_signatures(*object, store, device_key.user_id, device_key.device_id, viewer_user_id);
    return object;
}

auto published_cross_signing_key(database::PersistentStore const& store, std::string_view user_id,
                                 std::string_view key_type, std::optional<std::string_view> viewer_user_id)
    -> std::optional<canonicaljson::Object>
{
    for (auto const& key : store.cross_signing_keys)
    {
        if (key.user_id != user_id || key.key_type != key_type)
        {
            continue;
        }
        auto object = parsed_object(key.json);
        if (!object.has_value())
        {
            return std::nullopt;
        }
        if (auto const key_id = cross_signing_key_id(*object); key_id.has_value())
        {
            merge_visible_key_signatures(*object, store, user_id, *key_id, viewer_user_id);
        }
        return object;
    }
    return std::nullopt;
}

} // namespace merovingian::federation
