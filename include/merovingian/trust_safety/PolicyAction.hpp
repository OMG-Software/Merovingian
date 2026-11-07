// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::trust_safety
{

enum class PolicyAction
{
    allow,
    deny,
    quarantine,
    lock_account,
    suspend_account,
    accept_report,
};

} // namespace merovingian::trust_safety
