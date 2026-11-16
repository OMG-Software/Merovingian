// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/AccountDeviceRow.hpp"
#include "merovingian/oauth/AccountPageFrame.hpp"
#include "merovingian/oauth/AccountSignInInput.hpp"
#include "merovingian/oauth/HtmlName.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/Page.hpp"

#include <array>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::oauth
{

// The account pages at `/_merovingian/account` (spec "Account management", plan phase 8): pure functions of their
// inputs, built only with the Page renderer, English and fixed text (ADR-0763). The handler sends each with
// `page_headers()`.
//
// Every form posts to `account_path` with a submit button named `action`; every form of a signed-in page also carries
// the session's form token in the hidden field `form_token`. The names below are the ones the handler reads.

// The spec's account management actions (spec "Account management URL actions"), all of which these pages implement.
inline constexpr auto account_action_profile = std::string_view{"org.matrix.profile"};
inline constexpr auto account_action_devices_list = std::string_view{"org.matrix.devices_list"};
inline constexpr auto account_action_device_view = std::string_view{"org.matrix.device_view"};
inline constexpr auto account_action_device_delete = std::string_view{"org.matrix.device_delete"};
inline constexpr auto account_action_account_deactivate = std::string_view{"org.matrix.account_deactivate"};
inline constexpr auto account_action_cross_signing_reset = std::string_view{"org.matrix.cross_signing_reset"};

// The six actions in the order `account_management_actions_supported` advertises them. Nothing that is not
// implemented is listed.
[[nodiscard]] constexpr auto account_management_actions() noexcept -> std::array<std::string_view, 6U>
{
    return {account_action_profile,       account_action_devices_list,       account_action_device_view,
            account_action_device_delete, account_action_account_deactivate, account_action_cross_signing_reset};
}

// The `action` that one of the six names, or nullopt for anything else (absent, unknown, a different case).
[[nodiscard]] auto account_management_action(std::optional<std::string_view> action) noexcept
    -> std::optional<std::string_view>;
// Whether `action` takes the `device_id` parameter (spec: "Actions which don't support the device ID will ignore it").
[[nodiscard]] auto account_action_takes_device(std::string_view action) noexcept -> bool;

// The address of the account page for `action` and, when given, `device_id`: `account_url` (`OAuthBaseUrl::url(
// account_path)`) with `?action=` and `&device_id=`, each value percent-encoded (`percent_encode_redirect_value`) so
// nothing in it can change the query's shape. Every link between the pages, the redirect after sign-in and the
// `m.oauth` stage's URL are built here.
[[nodiscard]] auto account_action_address(std::string_view account_url, std::string_view action,
                                          std::optional<std::string_view> device_id = std::nullopt) -> std::string;

// Form field names.
inline constexpr auto account_form_token_field = HtmlName{"form_token"};
inline constexpr auto account_next_action_field = HtmlName{"next_action"};
inline constexpr auto account_next_device_field = HtmlName{"next_device_id"};
inline constexpr auto account_device_field = HtmlName{"device_id"};
inline constexpr auto account_current_password_field = HtmlName{"current_password"};
inline constexpr auto account_new_password_field = HtmlName{"new_password"};
inline constexpr auto account_new_password_confirm_field = HtmlName{"new_password_confirm"};
// The values of `action` the forms post.
inline constexpr auto account_post_sign_in = HtmlName{"sign_in"};
inline constexpr auto account_post_sign_out = HtmlName{"sign_out"};
inline constexpr auto account_post_show_password = HtmlName{"show_password"};
inline constexpr auto account_post_change_password = HtmlName{"change_password"};
inline constexpr auto account_post_delete_device = HtmlName{"delete_device"};
inline constexpr auto account_post_deactivate = HtmlName{"deactivate"};
inline constexpr auto account_post_approve_reset = HtmlName{"approve_cross_signing_reset"};

// The sign-in form: username and password, and the requested action and device in hidden fields.
[[nodiscard]] auto account_sign_in_page(AccountSignInInput const& input) -> Page;
// The overview (`org.matrix.profile`): the user ID and display name (read only, none when `display_name` is nullopt or
// cannot be shown), links to the other pages and the button that opens the password form.
[[nodiscard]] auto account_overview_page(AccountPageFrame const& frame, std::optional<std::string_view> display_name)
    -> Page;
// `org.matrix.devices_list`: one entry per device with its ID, display name and, for an OAuth device, its client's
// name, each linking to its device page.
[[nodiscard]] auto account_devices_page(AccountPageFrame const& frame, std::span<AccountDeviceRow const> devices)
    -> Page;
// `org.matrix.device_view`: one device's details and a link to sign it out.
[[nodiscard]] auto account_device_page(AccountPageFrame const& frame, AccountDeviceRow const& device) -> Page;
// `org.matrix.device_delete`: a confirmation naming the device, with the button that signs it out.
[[nodiscard]] auto account_device_delete_page(AccountPageFrame const& frame, AccountDeviceRow const& device) -> Page;
// The answer for a device ID the user does not hold: the same page whether it never existed or is another user's.
[[nodiscard]] auto account_unknown_device_page(AccountPageFrame const& frame) -> Page;
// The password form: the current password, the new one twice, and what a change does to the other sessions.
[[nodiscard]] auto account_password_page(AccountPageFrame const& frame, std::optional<HtmlText> const& error) -> Page;
// `org.matrix.account_deactivate`: what deactivation does, and the password again.
[[nodiscard]] auto account_deactivate_page(AccountPageFrame const& frame, std::optional<HtmlText> const& error) -> Page;
// `org.matrix.cross_signing_reset`: that the user's encryption identity will be replaced and other users will see them
// as unverified, and the approve button.
[[nodiscard]] auto account_cross_signing_reset_page(AccountPageFrame const& frame) -> Page;
// A signed-in page that reports what was done (or what failed): `title`, `message` and the links back.
[[nodiscard]] auto account_result_page(AccountPageFrame const& frame, HtmlText title, HtmlText const& message) -> Page;
// A page with no session: `title`, `message` and a link to sign in again at `account_url`.
[[nodiscard]] auto account_signed_out_page(HtmlText title, HtmlText const& message, std::string_view account_url)
    -> Page;

} // namespace merovingian::oauth
