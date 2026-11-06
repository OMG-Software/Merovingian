// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::federation
{

// Result of a federation `query/directory` lookup. found=false means the alias
// is unknown to this server and the handler responds 404 M_NOT_FOUND.
struct FederationDirectory final
{
    bool found{false};
    std::string room_id{};
    std::vector<std::string> servers{};
};

} // namespace merovingian::federation
