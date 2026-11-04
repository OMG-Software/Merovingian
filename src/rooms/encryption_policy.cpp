// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/rooms/encryption_policy.hpp"

#include <algorithm>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace merovingian::rooms
{

auto room_is_private(RoomPreset preset) noexcept -> bool
{
    return preset == RoomPreset::private_chat || preset == RoomPreset::trusted_private_chat;
}

auto room_creation_encryption_policy(RoomCreationEncryptionRequest request) -> RoomCreationEncryptionDecision
{
    auto const& settings = request.settings;
    auto const private_room = room_is_private(request.preset);
    auto const public_room = !private_room;

    // Each requirement keeps its own refusal reason, in this order.
    auto reason = std::string{};
    if (request.direct_message && settings.require_for_direct_messages)
    {
        reason = "direct messages must be encrypted";
    }
    else if (request.federated && private_room && settings.block_unencrypted_federated_private_rooms)
    {
        reason = "federated private rooms must be encrypted";
    }
    else if (private_room && settings.require_for_private_rooms)
    {
        reason = "private rooms must be encrypted";
    }
    else if (public_room && !settings.allow_unencrypted_public_rooms)
    {
        reason = "public rooms must be encrypted";
    }
    auto const encryption_required = !reason.empty();
    auto const encryption_enabled_by_default =
        settings.default_for_new_rooms && (private_room || request.direct_message);

    if (request.encryption == RoomEncryptionRequest::unencrypted && encryption_required)
    {
        return {false, true, encryption_enabled_by_default, false, std::move(reason)};
    }

    auto const encryption_enabled = request.encryption == RoomEncryptionRequest::encrypted ||
                                    (request.encryption == RoomEncryptionRequest::unspecified &&
                                     (encryption_required || encryption_enabled_by_default));

    return {true, encryption_required, encryption_enabled_by_default, encryption_enabled, {}};
}

auto encryption_request_from_initial_state(std::span<canonicaljson::Value const> initial_state) -> RoomEncryptionRequest
{
    // The entries room creation stores, in order (spec: initial_state events are sent "in the
    // order that they are listed"): objects with a string type and an object content. A state_key
    // that is absent or not a string is stored as the empty key.
    auto request = RoomEncryptionRequest::unspecified;
    for (auto const& item : initial_state)
    {
        auto const* entry = std::get_if<canonicaljson::Object>(&item.storage());
        if (entry == nullptr)
        {
            continue;
        }
        auto const find = [entry](std::string_view key) -> canonicaljson::Value const* {
            auto const member = std::ranges::find_if(*entry, [key](auto const& m) {
                return m.key == key;
            });
            return member == entry->end() ? nullptr : member->value.get();
        };
        auto const* type = find("type");
        auto const* content = find("content");
        auto const* type_name = type == nullptr ? nullptr : std::get_if<std::string>(&type->storage());
        auto const* content_object =
            content == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&content->storage());
        if (type_name == nullptr || content_object == nullptr || *type_name != "m.room.encryption")
        {
            continue;
        }
        auto const* state_key = find("state_key");
        auto const* state_key_name = state_key == nullptr ? nullptr : std::get_if<std::string>(&state_key->storage());
        if (state_key_name != nullptr && !state_key_name->empty())
        {
            continue;
        }
        auto const algorithm = std::ranges::find_if(*content_object, [](auto const& m) {
            return m.key == "algorithm";
        });
        auto const* algorithm_name =
            algorithm == content_object->end() ? nullptr : std::get_if<std::string>(&algorithm->value->storage());
        request = algorithm_name != nullptr && *algorithm_name == "m.megolm.v1.aes-sha2"
                      ? RoomEncryptionRequest::encrypted
                      : RoomEncryptionRequest::unencrypted;
    }
    return request;
}

auto encrypted_event_payload_is_loggable(std::string_view payload) noexcept -> bool
{
    return payload.empty();
}

auto make_encrypted_event_log_summary(std::string_view event_type, std::string_view room_id, std::string_view sender,
                                      std::string_view encrypted_payload) -> EncryptedEventLogSummary
{
    auto payload = std::string{"[encrypted-payload:redacted]"};
    if (encrypted_payload.empty())
    {
        payload = "[encrypted-payload:empty]";
    }

    return {std::string{event_type}, std::string{room_id}, std::string{sender}, payload};
}

auto encrypted_event_log_summary_text(EncryptedEventLogSummary const& summary) -> std::string
{
    return "encrypted event type=" + summary.event_type + " room_id=" + summary.room_id + " sender=" + summary.sender +
           " payload=" + summary.payload;
}

} // namespace merovingian::rooms
