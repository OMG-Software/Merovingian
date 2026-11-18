// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::oauth
{

// What every page of a signed-in account-page session shows and carries (`AccountPages.hpp`). Every view is borrowed
// for the call. Each string is escaped by the page builder; one that cannot be shown is replaced by fixed text.
struct AccountPageFrame final
{
    // `server.server_name`, named at the top of the page.
    std::string_view server_name{};
    // The signed-in user, named at the top of the page.
    std::string_view user_id{};
    // The session's form token, the hidden `form_token` field of every form. A page whose token cannot be shown holds
    // no form.
    std::string_view form_token{};
    // `OAuthBaseUrl::url(account_path)`: the base of every link between the pages, which add only `?action=` and
    // `&device_id=`.
    std::string_view account_url{};
};

} // namespace merovingian::oauth
