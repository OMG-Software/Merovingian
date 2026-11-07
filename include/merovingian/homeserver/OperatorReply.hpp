// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// An answer from an operator route. The operator surface answers an error with a plain-text line and a
// result with a JSON object (the same convention as /_merovingian/admin/audit, which is JSON, and the
// admin_auth_denied lines, which are text), never with a Matrix `errcode` body (ADR-0504).
struct OperatorReply final
{
    std::uint16_t status{500U};
    std::string body{};
    bool json{false};
};

} // namespace merovingian::homeserver
