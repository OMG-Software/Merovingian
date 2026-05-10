// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/rooms/encryption_policy.hpp>

#include <string>

namespace merovingian::rooms
{

auto room_is_private(RoomPreset preset) noexcept -> bool
{
    return preset == RoomPreset::private_chat || preset == RoomPreset::trusted_private_chat;
}

auto room_creation_encryption_policy(RoomCreationEncryptionRequest request) -> RoomCreationEncryptionDecision
{
    auto const private_room = room_is_private(request.preset);
    auto const encryption_required = private_room || request.direct_message;
    auto const encryption_enabled_by_default = encryption_required;

    if (request.direct_message && !request.encryption_requested)
    {
        return {false, true, true, "direct messages must be encrypted"};
    }
    if (private_room && !request.encryption_requested)
    {
        return {false, true, true, "private rooms must be encrypted"};
    }
    if (request.federated && private_room && !request.encryption_requested)
    {
        return {false, true, true, "federated private rooms must be encrypted"};
    }

    return {true, encryption_required, encryption_enabled_by_default, {}};
}

auto encrypted_event_payload_is_loggable(std::string_view payload) noexcept -> bool
{
    return payload.empty();
}

auto make_encrypted_event_log_summary(
    std::string_view event_type,
    std::string_view room_id,
    std::string_view sender,
    std::string_view encrypted_payload
) -> EncryptedEventLogSummary
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
    return "encrypted event type=" + summary.event_type + " room_id=" + summary.room_id + " sender=" + summary.sender
        + " payload=" + summary.payload;
}

} // namespace merovingian::rooms
