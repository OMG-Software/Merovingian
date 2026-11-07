// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::push
{

enum class EmailDigestAdmission : std::uint8_t
{
    // An email is now due; it was not before.
    scheduled,
    // An email was already due or being sent; this notification will be in it, or in the one that
    // follows it.
    folded,
    // email_digest_queue_capacity pushers are tracked and none could be released.
    queue_full,
};

} // namespace merovingian::push
