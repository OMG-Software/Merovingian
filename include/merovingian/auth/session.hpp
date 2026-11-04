// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/identity.hpp"
#include "merovingian/auth/token.hpp"

#include <chrono>
#include <string>
#include <string_view>

namespace merovingian::auth
{

struct RegistrationPolicy final
{
    bool enabled{false};
    bool require_token{true};
    bool token_present{false};
};

struct RegistrationPolicyDecision final
{
    bool allowed{false};
    std::string reason{};
};

[[nodiscard]] auto registration_policy(RegistrationPolicy policy) -> RegistrationPolicyDecision;

} // namespace merovingian::auth
