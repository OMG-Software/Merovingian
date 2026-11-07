// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::config
{

enum class RuntimeConfigApplyResult : unsigned char
{
    applied,
    unchanged,
    restart_required,
};

} // namespace merovingian::config
