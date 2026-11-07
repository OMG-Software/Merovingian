// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::federation
{

struct AuthorisingSignatureKey final
{
    std::string server_name{};
    std::vector<std::string> key_ids{};
};

} // namespace merovingian::federation
