// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::crypto
{

// The decoded parts of an HS256 token whose MAC `verify_hs256_token` checked. Nothing in them has been judged: the
// caller parses both and checks every claim it relies on.
struct VerifiedHs256Token final
{
    std::string header_json{};
    std::string payload_json{};
};

} // namespace merovingian::crypto
