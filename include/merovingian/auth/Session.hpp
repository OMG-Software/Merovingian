// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/RegistrationPolicy.hpp"
#include "merovingian/auth/RegistrationPolicyDecision.hpp"
#include "merovingian/auth/Token.hpp"

#include <chrono>
#include <string>
#include <string_view>

namespace merovingian::auth
{

[[nodiscard]] auto registration_policy(RegistrationPolicy policy) -> RegistrationPolicyDecision;

} // namespace merovingian::auth
