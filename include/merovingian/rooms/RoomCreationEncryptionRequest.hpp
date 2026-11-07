// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/EncryptionSecurityConfig.hpp"
#include "merovingian/rooms/RoomEncryptionRequest.hpp"
#include "merovingian/rooms/RoomPreset.hpp"

namespace merovingian::rooms
{

struct RoomCreationEncryptionRequest final
{
    RoomPreset preset{RoomPreset::private_chat};
    bool direct_message{false};
    bool federated{false};
    RoomEncryptionRequest encryption{RoomEncryptionRequest::unspecified};
    config::EncryptionSecurityConfig settings{};
};

} // namespace merovingian::rooms
