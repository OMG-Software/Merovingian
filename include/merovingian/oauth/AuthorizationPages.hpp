// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/AccountFormInput.hpp"
#include "merovingian/oauth/ConsentPageInput.hpp"
#include "merovingian/oauth/DeviceConsentPageInput.hpp"
#include "merovingian/oauth/HtmlName.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/Page.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <optional>
#include <string_view>

namespace merovingian::oauth
{

// The pages of the authorisation endpoint (`GET` and `POST /_merovingian/oauth2/authorize`, ADR-0815): pure functions
// of their inputs, built only with the Page renderer, English and fixed text. The handler sends each with
// `page_headers()`, the consent page with `page_headers(redirect_target)`.
//
// Every form posts to `authorize_path` with the hidden field `pending` and a submit button named `action`; these names
// are the ones the handler reads.
inline constexpr auto pending_field = HtmlName{"pending"};
inline constexpr auto action_field = HtmlName{"action"};
inline constexpr auto username_field = HtmlName{"username"};
inline constexpr auto password_field = HtmlName{"password"};
inline constexpr auto password_confirm_field = HtmlName{"password_confirm"};
inline constexpr auto registration_token_field = HtmlName{"registration_token"};
// The values of `action`.
inline constexpr auto action_login = HtmlName{"login"};
inline constexpr auto action_register = HtmlName{"register"};
inline constexpr auto action_show_login = HtmlName{"show_login"};
inline constexpr auto action_show_register = HtmlName{"show_register"};
inline constexpr auto action_approve = HtmlName{"approve"};
inline constexpr auto action_deny = HtmlName{"deny"};

// The login form: username (`autocomplete="username"`, prefilled when `input.username` can be shown) and password
// (`current-password`), and, when `input.offer_other_form`, a second form that switches to registration. When the
// pending identifier cannot be shown the page says the sign-in cannot continue and holds no form.
[[nodiscard]] auto login_page(AccountFormInput const& input) -> Page;

// The registration form: username, password and its repetition (`new-password`), a registration token when
// `input.registration_token_required`, and, when `input.offer_other_form`, a second form that switches to sign-in.
[[nodiscard]] auto registration_page(AccountFormInput const& input) -> Page;

// The consent page: the client's name (a fixed phrase when it has none or it cannot be shown), the host of its
// `client_uri`, where the browser is sent next (the host of an `http` or `https` `redirect_target`, else its scheme),
// the user ID, the device ID, a plain statement that the application gets full access to the account, links to the
// policy and terms when registered, a notice when the device's current session is replaced, and the approve and deny
// buttons.
[[nodiscard]] auto consent_page(ConsentPageInput const& input, ParsedUri const& redirect_target) -> Page;

// The confirmation page of the legacy login hand-off (plan P10, ADR-0802): the user signed in, and the application
// at `target` (its host for an `http` or `https` address, else its scheme) is about to receive a login token for the
// account. Continue (`approve`) and cancel (`deny`) post to `authorize_path`. Sent with `page_headers(target)`.
[[nodiscard]] auto hand_off_page(std::string_view pending_id, std::string_view user_id, ParsedUri const& target)
    -> Page;
// The page a cancelled hand-off ends on: nothing is sent to the application.
[[nodiscard]] auto hand_off_cancelled_page() -> Page;
// The pages of the device authorization grant (plan P11; ADR-0804, ADR-0806). None redirects anywhere: each is sent
// with `page_headers()`.
//
// The field the link page's form posts the typed code in.
inline constexpr auto user_code_field = HtmlName{"user_code"};
// The link page (`GET` and `POST /_merovingian/oauth2/link`): one input for the code the other device shows, posting
// to `link_path`. `user_code`, a stored-form code, is prefilled as `XXXX-XXXX` (from `verification_uri_complete`);
// `error` is a fixed message about the last attempt.
[[nodiscard]] auto device_link_page(std::optional<std::string_view> user_code, std::optional<HtmlText> const& error)
    -> Page;
// The consent page of a device sign-in. It opens with the warning that a different device is being signed in and that
// the user should continue only if they started this themselves and the code matches; then the code, the application,
// its website, the account and the device ID; the statement of full access; the notice when the device's session is
// replaced; and Allow and Deny posting to `authorize_path`.
[[nodiscard]] auto device_consent_page(DeviceConsentPageInput const& input) -> Page;
// The pages a device sign-in ends on: approved (return to the other device, which finishes on its own) and denied.
[[nodiscard]] auto device_approved_page() -> Page;
[[nodiscard]] auto device_denied_page() -> Page;

// A page that only says what went wrong: `title` and one paragraph, no form.
[[nodiscard]] auto error_page(HtmlText title, HtmlText const& message) -> Page;

} // namespace merovingian::oauth
