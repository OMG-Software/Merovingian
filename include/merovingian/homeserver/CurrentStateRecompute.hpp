// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/CurrentStateRecomputeStatus.hpp"

#include <string>

namespace merovingian::homeserver
{

struct CurrentStateRecompute final
{
    CurrentStateRecomputeStatus status{CurrentStateRecomputeStatus::resolved};
    // Why the extremities could not be resolved; empty unless `status` is `refused`.
    std::string reason{};

    // True only when current state is the resolution of the extremities.
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return status == CurrentStateRecomputeStatus::resolved;
    }
};

} // namespace merovingian::homeserver
