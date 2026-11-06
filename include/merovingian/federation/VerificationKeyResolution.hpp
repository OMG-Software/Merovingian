// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/FederationKeyRecord.hpp"

#include <optional>

namespace merovingian::federation
{

struct VerificationKeyResolution final
{
    std::optional<FederationKeyRecord> key{};
    bool locally_denied{false};
};

} // namespace merovingian::federation
