// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::federation
{

// Verified peer identity for an inbound federation request whose X-Matrix
// signature has been checked by the main process.
struct VerifiedFederationIdentity final
{
    std::string origin{};
    std::string key_id{};
};

} // namespace merovingian::federation
