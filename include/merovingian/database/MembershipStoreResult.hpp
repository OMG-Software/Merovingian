// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

enum class MembershipStoreResult
{
    stored,
    already_exists,
    error,
};

} // namespace merovingian::database
