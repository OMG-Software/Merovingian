// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::auth
{

struct RegistrationPolicy final
{
    bool enabled{false};
    bool require_token{true};
    bool token_present{false};
};

} // namespace merovingian::auth
