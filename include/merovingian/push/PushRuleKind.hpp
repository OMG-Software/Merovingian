// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::push
{

// The five push rule kinds, checked in this exact precedence order per spec:
// override > content > room > sender > underride.
enum class PushRuleKind
{
    override_kind,
    content,
    room,
    sender,
    underride,
};

} // namespace merovingian::push
