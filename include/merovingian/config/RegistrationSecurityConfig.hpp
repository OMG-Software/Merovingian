// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::config
{

struct RegistrationSecurityConfig final
{
    bool enabled{false};
    bool require_token{true};
    std::string token_file{};
    // ADR-0232: `require_token=false` with `enabled=true` is a startup error
    // unless this is set. Open registration still uses UIA, with the single
    // stage m.login.dummy.
    bool allow_open_registration{false};
};

} // namespace merovingian::config
