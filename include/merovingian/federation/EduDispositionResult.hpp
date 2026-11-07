// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/EduDispositionStatus.hpp"

#include <string>

namespace merovingian::federation
{

struct EduDispositionResult final
{
    EduDispositionStatus status{EduDispositionStatus::dropped_unknown_type};
    std::string reason{};
};

} // namespace merovingian::federation
