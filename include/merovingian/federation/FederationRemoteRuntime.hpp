// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/FederationKeyRecord.hpp"
#include "merovingian/federation/security.hpp"

#include <string>

namespace merovingian::federation
{

struct FederationRemoteRuntime final
{
    std::string server_name{};
    RemoteTrustState trust{};
    FederationKeyRecord signing_key{};
    RemoteServerRecord discovery{};
};

} // namespace merovingian::federation
