// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"

#include <string>

namespace merovingian::canonicaljson
{

struct SerializeResult final
{
    std::string output{};
    CanonicalJsonError error{CanonicalJsonError::none};
};

} // namespace merovingian::canonicaljson
