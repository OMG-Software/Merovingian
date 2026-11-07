// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::core
{

enum class ErrorCode
{
    none = 0,
    invalid_argument,
    io_failure,
    parse_failure,
    internal_failure,
};

} // namespace merovingian::core
