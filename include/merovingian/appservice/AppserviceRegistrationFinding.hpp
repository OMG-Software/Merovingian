// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::appservice
{

// Findings from validating a set of freshly-parsed registrations before
// they become an AppserviceRegistry: spec v1.19 "If the homeserver in
// question has multiple application services, each as_token and id MUST be
// unique per application service as these are used to identify the
// application service. The homeserver MUST enforce this."
struct AppserviceRegistrationFinding final
{
    std::string source{}; // file path, for operator diagnostics
    std::string message{};
};

} // namespace merovingian::appservice
