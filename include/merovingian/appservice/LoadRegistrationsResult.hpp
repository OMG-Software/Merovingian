// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppserviceRegistrationFinding.hpp"
#include "merovingian/appservice/AppserviceRegistry.hpp"

#include <vector>

namespace merovingian::appservice
{

// What `load_registrations` returns: the registry of registrations that passed, and a finding for
// every file it skipped.
struct LoadRegistrationsResult final
{
    AppserviceRegistry registry{};
    std::vector<AppserviceRegistrationFinding> findings{};
};

} // namespace merovingian::appservice
