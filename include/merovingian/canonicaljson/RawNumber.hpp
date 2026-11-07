// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::canonicaljson
{

// A number Canonical JSON cannot represent (a float, or an integer outside its range), exactly as it was received.
// Only parse_preserving_numbers makes one; serialize_canonical writes it back verbatim and
// serialize_canonical_strict refuses it, so it can never reach a hash or a signature this server makes.
struct RawNumber final
{
    std::string token{};
};

} // namespace merovingian::canonicaljson
