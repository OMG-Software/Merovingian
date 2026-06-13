// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>

namespace merovingian::rooms
{

enum class RoomPreset
{
    public_chat,
    private_chat,
    trusted_private_chat,
};

enum class RoomEncryptionRequest
{
    unspecified,
    encrypted,
    unencrypted,
};

struct RoomCreationEncryptionRequest final
{
    RoomPreset preset{RoomPreset::private_chat};
    bool direct_message{false};
    bool federated{false};
    RoomEncryptionRequest encryption{RoomEncryptionRequest::unspecified};
};

struct RoomCreationEncryptionDecision final
{
    bool allowed{false};
    bool encryption_required{false};
    bool encryption_enabled_by_default{false};
    bool encryption_enabled{false};
    std::string reason{};
};

struct EncryptedEventLogSummary final
{
    std::string event_type{};
    std::string room_id{};
    std::string sender{};
    std::string payload{};
};

[[nodiscard]] auto room_is_private(RoomPreset preset) noexcept -> bool;
[[nodiscard]] auto room_creation_encryption_policy(RoomCreationEncryptionRequest request)
    -> RoomCreationEncryptionDecision;
[[nodiscard]] auto encrypted_event_payload_is_loggable(std::string_view payload) noexcept -> bool;
[[nodiscard]] auto make_encrypted_event_log_summary(std::string_view event_type, std::string_view room_id,
                                                    std::string_view sender, std::string_view encrypted_payload)
    -> EncryptedEventLogSummary;
[[nodiscard]] auto encrypted_event_log_summary_text(EncryptedEventLogSummary const& summary) -> std::string;

} // namespace merovingian::rooms
