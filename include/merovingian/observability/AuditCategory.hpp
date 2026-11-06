// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::observability
{

enum class AuditCategory
{
    auth,
    key_lifecycle,
    policy,
    moderation,
    admin,
};

} // namespace merovingian::observability
