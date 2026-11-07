// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/AccountState.hpp"

#include <string>

namespace merovingian::auth
{

struct UserIdentity final
{
    std::string user_id{};
    AccountState state{AccountState::active};
    bool password_login_enabled{true};
    bool admin{false};
};

} // namespace merovingian::auth
