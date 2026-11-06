// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct FederationResponse final
{
    std::uint16_t status{500U};
    std::string body{};
    // Non-empty overrides the default application/json Content-Type header on
    // the HTTP response. Used by the federation media download endpoint to emit
    // multipart/mixed.
    std::string content_type{};
};

} // namespace merovingian::federation
