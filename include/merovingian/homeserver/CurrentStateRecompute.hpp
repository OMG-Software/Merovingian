// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MembershipProjection.hpp"
#include "merovingian/homeserver/CurrentStateRecomputeStatus.hpp"

#include <string>
#include <vector>

namespace merovingian::homeserver
{

struct CurrentStateRecompute final
{
    CurrentStateRecomputeStatus status{CurrentStateRecomputeStatus::resolved};
    // Why the extremities could not be resolved; empty unless `status` is `refused`.
    std::string reason{};
    // The membership rows this recomputation corrected, already stored (ADR-0615). The caller applies each to the live
    // roster.
    std::vector<database::MembershipProjection> membership_changes{};

    // True only when current state is the resolution of the extremities.
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return status == CurrentStateRecomputeStatus::resolved;
    }
};

} // namespace merovingian::homeserver
