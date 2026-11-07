// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/EncryptionSecurityConfig.hpp"
#include "merovingian/rooms/EncryptedEventLogSummary.hpp"       // split-shim
#include "merovingian/rooms/RoomCreationEncryptionDecision.hpp" // split-shim
#include "merovingian/rooms/RoomCreationEncryptionRequest.hpp"  // split-shim
#include "merovingian/rooms/RoomEncryptionRequest.hpp"          // split-shim
#include "merovingian/rooms/RoomPreset.hpp"                     // split-shim

#include <span>
#include <string>
#include <string_view>

namespace merovingian::rooms
{

// The only algorithm the spec lists for m.room.encryption `algorithm` ("One of: `[m.megolm.v1.aes-sha2]`").
// This is the only place that names it: createRoom's effective entry and the state PUT both ask it.
[[nodiscard]] auto encryption_algorithm_is_valid(std::string_view algorithm) noexcept -> bool;
[[nodiscard]] auto room_is_private(RoomPreset preset) noexcept -> bool;
[[nodiscard]] auto room_creation_encryption_policy(RoomCreationEncryptionRequest request)
    -> RoomCreationEncryptionDecision;
// What a createRoom request asks of encryption, read from `initial_state`. The Matrix API has
// no way to ask for an unencrypted room, so: no effective entry is `unspecified`; the effective
// entry is the LAST m.room.encryption entry that room creation would store under the empty state
// key (an object with an object `content`; an absent or non-string state_key is the empty key); it is
// `encrypted` only when content.algorithm is exactly m.megolm.v1.aes-sha2, else `unencrypted`.
[[nodiscard]] auto encryption_request_from_initial_state(std::span<canonicaljson::Value const> initial_state)
    -> RoomEncryptionRequest;
[[nodiscard]] auto encrypted_event_payload_is_loggable(std::string_view payload) noexcept -> bool;
[[nodiscard]] auto make_encrypted_event_log_summary(std::string_view event_type, std::string_view room_id,
                                                    std::string_view sender, std::string_view encrypted_payload)
    -> EncryptedEventLogSummary;
[[nodiscard]] auto encrypted_event_log_summary_text(EncryptedEventLogSummary const& summary) -> std::string;

} // namespace merovingian::rooms
