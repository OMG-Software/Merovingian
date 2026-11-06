// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::trust_safety
{

enum class PolicySurface
{
    federation,
    media,
    registration,
    room,
    account,
};

enum class PolicyAction
{
    allow,
    deny,
    quarantine,
    lock_account,
    suspend_account,
    accept_report,
};

enum class ReviewTarget
{
    federation_server,
    media,
    room,
};

} // namespace merovingian::trust_safety
