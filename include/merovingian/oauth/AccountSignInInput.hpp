// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlText.hpp"

#include <optional>
#include <string_view>

namespace merovingian::oauth
{

// What the account pages' sign-in form shows and carries (`account_sign_in_page`). Every view is borrowed for the call.
struct AccountSignInInput final
{
    // `server.server_name`, named in the opening line.
    std::string_view server_name{};
    // The account management action (spec "Account management URL actions") the browser asked for, carried in a hidden
    // field so the user lands on that page after signing in. Only one of `account_management_actions()`.
    std::optional<std::string_view> next_action{};
    // The device ID the browser asked for, carried with `next_action`. Only one that passed
    // `auth::device_id_is_valid`, and only with a device action.
    std::optional<std::string_view> next_device_id{};
    // A username to prefill (what the user typed when the form is shown again), or none.
    std::optional<std::string_view> username{};
    // A fixed message about the last attempt, shown as an error box.
    std::optional<HtmlText> error{};
    // A fixed notice, such as "You have signed out".
    std::optional<HtmlText> notice{};
};

} // namespace merovingian::oauth
