// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

struct FederationRequestSignature final
{
    std::string origin{};
    std::string key_id{};
    std::string signature{};
    bool canonical_json_verified{false};
};

} // namespace merovingian::federation
