// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/RemoteKeyResponse.hpp"

#include <string>

namespace merovingian::federation
{

struct RemoteKeyFetchResult final
{
    bool ok{false};
    RemoteKeyResponse response{};
    std::string reason{};
};

} // namespace merovingian::federation
