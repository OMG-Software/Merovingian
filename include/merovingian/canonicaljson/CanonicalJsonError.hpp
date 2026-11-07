// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::canonicaljson
{

enum class CanonicalJsonError : unsigned char
{
    none,
    duplicate_object_key,
    invalid_string,
    float_not_allowed,
};

} // namespace merovingian::canonicaljson
