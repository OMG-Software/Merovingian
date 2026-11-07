// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/value.hpp"

namespace merovingian::canonicaljson
{

struct ParseResult final
{
    Value value{};
    ParseError error{ParseError::none};
};

} // namespace merovingian::canonicaljson
