// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/HtmlText.hpp"

#include <optional>
#include <string_view>

namespace merovingian::oauth
{

// What the login page and the registration page of an authorisation show (`login_page`, `registration_page`). Every
// view is borrowed for the call. The strings are attacker-chosen or come from configuration: each is escaped, and one
// that cannot be shown is replaced by fixed text, never shown raw.
struct AccountFormInput final
{
    // `server.server_name`, named in the page's opening line.
    std::string_view server_name{};
    // The pending authorisation identifier, the page form's hidden `pending` field.
    std::string_view pending_id{};
    // A username to prefill (a login hint, or what the user typed when the form is shown again), or none.
    std::optional<std::string_view> username{};
    // A fixed message about the last attempt, shown as an error box (the handler chooses it, never a request).
    std::optional<HtmlText> error{};
    // A fixed notice, such as "this server does not accept new accounts".
    std::optional<HtmlText> notice{};
    // Whether to offer the other form: registration from the login page, sign-in from the registration page.
    bool offer_other_form{false};
    // The registration page only: whether it asks for a registration token.
    bool registration_token_required{false};
};

} // namespace merovingian::oauth
