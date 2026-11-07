// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::rooms
{

struct RoomCreationEncryptionDecision final
{
    bool allowed{false};
    bool encryption_required{false};
    bool encryption_enabled_by_default{false};
    bool encryption_enabled{false};
    std::string reason{};
};

} // namespace merovingian::rooms
