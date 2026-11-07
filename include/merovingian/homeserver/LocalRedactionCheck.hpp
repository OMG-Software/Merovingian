// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"

namespace merovingian::homeserver
{

enum class LocalRedactionCheck
{
    permitted,
    // The event the redaction names is held here, but in another room.
    target_unknown,
    // The sender may not redact it (or it may not be redacted at all).
    forbidden,
};

} // namespace merovingian::homeserver
