// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct FederationTransaction final
{
    std::string origin{};
    std::string transaction_id{};
    std::vector<std::string> pdus{};
    std::vector<std::string> edus{};
    std::size_t byte_size{0U};
};

} // namespace merovingian::federation
