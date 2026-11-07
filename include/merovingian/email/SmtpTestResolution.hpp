// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::email
{

// Test-only: connect to these addresses instead of resolving the relay's host, and trust this PEM
// instead of the system CA store. Never set in production.
struct SmtpTestResolution final
{
    std::vector<std::string> pinned_addresses{};
    std::string trusted_ca_pem{};
};

} // namespace merovingian::email
