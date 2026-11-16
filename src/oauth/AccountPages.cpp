// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/AccountPages.hpp"

#include "merovingian/oauth/AuthorizationPages.hpp"
#include "merovingian/oauth/AuthorizationRedirect.hpp"
#include "merovingian/oauth/HtmlLiteral.hpp"
#include "merovingian/oauth/OAuthPaths.hpp"
#include "merovingian/oauth/PageDetail.hpp"
#include "merovingian/oauth/PageForm.hpp"
#include "merovingian/oauth/SubmitButton.hpp"
#include "merovingian/oauth/TextInput.hpp"

#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace merovingian::oauth
{

namespace
{

    // The fixed phrase the consent page shows for a client with no name it can show.
    constexpr auto unnamed_client = HtmlLiteral{"An application with no name"};

    // `text` escaped, or `fallback` when HtmlText::escape refuses it: the raw value is never shown.
    [[nodiscard]] auto shown(std::string_view text, HtmlLiteral fallback) -> HtmlText
    {
        auto escaped = HtmlText::escape(text);
        return escaped.has_value() ? std::move(*escaped) : HtmlText{fallback};
    }

    // `prefix`, `value` and `suffix` as one escaped sentence, or `fallback` when the value cannot be shown.
    [[nodiscard]] auto sentence(std::string_view prefix, std::string_view value, std::string_view suffix,
                                HtmlLiteral fallback) -> HtmlText
    {
        if (value.empty())
        {
            return HtmlText{fallback};
        }
        auto text = std::string{prefix};
        text.append(value);
        text.append(suffix);
        return shown(text, fallback);
    }

    // A form posting `action` with the session's form token, or nullopt when the token cannot be shown (the page then
    // has no form).
    [[nodiscard]] auto session_form(AccountPageFrame const& frame) -> std::optional<PageForm>
    {
        auto token = HtmlText::escape(frame.form_token);
        if (!token.has_value())
        {
            return std::nullopt;
        }
        auto form = PageForm{account_path};
        form.hidden(account_form_token_field, std::move(*token));
        return form;
    }

    // The opening line every signed-in page has, naming the server and the user.
    auto add_signed_in_as(Page& page, AccountPageFrame const& frame) -> void
    {
        page.details(std::array{
            PageDetail{HtmlText{"Server"},       shown(frame.server_name, "this server")                    },
            PageDetail{HtmlText{"Signed in as"}, shown(frame.user_id,     "an account that cannot be shown")},
        });
    }

    // The links back to the overview and the device list, and the sign-out button, at the foot of every signed-in
    // page.
    auto add_footer(Page& page, AccountPageFrame const& frame) -> void
    {
        std::ignore =
            page.link(HtmlText{"Your account"}, account_action_address(frame.account_url, account_action_profile));
        std::ignore =
            page.link(HtmlText{"Your devices"}, account_action_address(frame.account_url, account_action_devices_list));
        if (auto form = session_form(frame); form.has_value())
        {
            std::ignore =
                form->button(SubmitButton{action_field, account_post_sign_out, HtmlText{"Sign out of this page"}});
            std::ignore = page.form(*form);
        }
    }

    auto add_error(Page& page, std::optional<HtmlText> const& error) -> void
    {
        if (error.has_value())
        {
            page.error(*error);
        }
    }

    [[nodiscard]] auto password_input(HtmlName name, HtmlText label, HtmlName autocomplete) -> TextInput
    {
        auto input = TextInput{name, std::move(label), autocomplete};
        input.concealed = true;
        return input;
    }

    // The details of one device: its ID, its name, and how it signed in.
    [[nodiscard]] auto device_details(AccountDeviceRow const& device) -> std::array<PageDetail, 3U>
    {
        auto const name = device.display_name.empty() ? HtmlText{"No name set"}
                                                      : shown(device.display_name, "A name that cannot be shown");
        auto signed_in_with = HtmlText{"A password, in the application"};
        if (device.oauth_session)
        {
            signed_in_with =
                device.client_name.has_value() ? shown(*device.client_name, unnamed_client) : HtmlText{unnamed_client};
        }
        return {
            PageDetail{HtmlText{"Device ID"}, shown(device.device_id, "a device that cannot be shown")},
            PageDetail{HtmlText{"Name"}, name},
            PageDetail{HtmlText{"Signed in with"}, std::move(signed_in_with)},
        };
    }

    // A link to `action` for `device`, labelled with the device ID (or fixed text when it cannot be shown).
    auto add_device_link(Page& page, AccountPageFrame const& frame, std::string_view label_prefix,
                         std::string_view action, AccountDeviceRow const& device) -> void
    {
        auto const label = sentence(label_prefix, device.device_id, "", "A device that cannot be shown");
        std::ignore = page.link(label, account_action_address(frame.account_url, action, device.device_id));
    }

} // namespace

auto account_action_address(std::string_view account_url, std::string_view action,
                            std::optional<std::string_view> device_id) -> std::string
{
    auto address = std::string{account_url};
    address.append("?action=");
    address.append(percent_encode_redirect_value(action));
    if (device_id.has_value())
    {
        address.append("&device_id=");
        address.append(percent_encode_redirect_value(*device_id));
    }
    return address;
}

auto account_management_action(std::optional<std::string_view> action) noexcept -> std::optional<std::string_view>
{
    if (!action.has_value())
    {
        return std::nullopt;
    }
    for (auto const known : account_management_actions())
    {
        if (*action == known)
        {
            return known;
        }
    }
    return std::nullopt;
}

auto account_action_takes_device(std::string_view action) noexcept -> bool
{
    return action == account_action_device_view || action == account_action_device_delete;
}

auto account_sign_in_page(AccountSignInInput const& input) -> Page
{
    auto page = Page{HtmlText{"Sign in to manage your account"}};
    page.paragraph(sentence("Sign in with your account on ", input.server_name, " to manage it.",
                            "Sign in with your account on this server to manage it."));
    if (input.notice.has_value())
    {
        page.notice(*input.notice);
    }
    add_error(page, input.error);
    auto form = PageForm{account_path};
    // The action and device are carried only when they can be shown; the handler validated both before.
    if (auto const action = account_management_action(input.next_action); action.has_value())
    {
        if (auto text = HtmlText::escape(*action); text.has_value())
        {
            form.hidden(account_next_action_field, std::move(*text));
        }
        if (input.next_device_id.has_value() && account_action_takes_device(*action))
        {
            if (auto text = HtmlText::escape(*input.next_device_id); text.has_value())
            {
                form.hidden(account_next_device_field, std::move(*text));
            }
        }
    }
    auto username = TextInput{username_field, HtmlText{"Username"}, HtmlName{"username"}};
    if (input.username.has_value())
    {
        username.value = HtmlText::escape(*input.username);
    }
    std::ignore = form.input(std::move(username));
    std::ignore = form.input(password_input(password_field, HtmlText{"Password"}, HtmlName{"current-password"}));
    std::ignore = form.button(SubmitButton{action_field, account_post_sign_in, HtmlText{"Sign in"}});
    std::ignore = page.form(form);
    page.paragraph(HtmlText{"You stay signed in to these pages for 15 minutes at most."});
    return page;
}

auto account_overview_page(AccountPageFrame const& frame, std::optional<std::string_view> display_name) -> Page
{
    auto page = Page{HtmlText{"Your account"}};
    add_signed_in_as(page, frame);
    auto const name = display_name.has_value() && !display_name->empty()
                          ? shown(*display_name, "A name that cannot be shown")
                          : HtmlText{"No display name set"};
    page.details(std::array{
        PageDetail{HtmlText{"User ID"}, shown(frame.user_id, "an account that cannot be shown")},
        PageDetail{HtmlText{"Display name"}, name},
    });
    page.paragraph(HtmlText{"Change your display name and avatar in your application."});
    std::ignore = page.link(HtmlText{"See and sign out your devices"},
                            account_action_address(frame.account_url, account_action_devices_list));
    std::ignore = page.link(HtmlText{"Reset your encryption identity"},
                            account_action_address(frame.account_url, account_action_cross_signing_reset));
    std::ignore = page.link(HtmlText{"Deactivate your account"},
                            account_action_address(frame.account_url, account_action_account_deactivate));
    if (auto form = session_form(frame); form.has_value())
    {
        std::ignore =
            form->button(SubmitButton{action_field, account_post_show_password, HtmlText{"Change your password"}});
        std::ignore = page.form(*form);
    }
    add_footer(page, frame);
    return page;
}

auto account_devices_page(AccountPageFrame const& frame, std::span<AccountDeviceRow const> devices) -> Page
{
    auto page = Page{HtmlText{"Your devices"}};
    add_signed_in_as(page, frame);
    if (devices.empty())
    {
        page.paragraph(HtmlText{"No device is signed in to your account."});
    }
    for (auto const& device : devices)
    {
        page.details(device_details(device));
        add_device_link(page, frame, "Details of ", account_action_device_view, device);
    }
    add_footer(page, frame);
    return page;
}

auto account_device_page(AccountPageFrame const& frame, AccountDeviceRow const& device) -> Page
{
    auto page = Page{HtmlText{"Device"}};
    add_signed_in_as(page, frame);
    page.details(device_details(device));
    add_device_link(page, frame, "Sign out ", account_action_device_delete, device);
    add_footer(page, frame);
    return page;
}

auto account_device_delete_page(AccountPageFrame const& frame, AccountDeviceRow const& device) -> Page
{
    auto page = Page{HtmlText{"Sign out a device"}};
    add_signed_in_as(page, frame);
    page.details(device_details(device));
    page.paragraph(HtmlText{"Signing this device out ends its session: the application on it can no longer use your "
                            "account, and the device is removed from your account."});
    auto device_value = HtmlText::escape(device.device_id);
    if (auto form = session_form(frame); form.has_value() && device_value.has_value())
    {
        form->hidden(account_device_field, std::move(*device_value));
        std::ignore =
            form->button(SubmitButton{action_field, account_post_delete_device, HtmlText{"Sign out this device"}});
        std::ignore = page.form(*form);
    }
    add_footer(page, frame);
    return page;
}

auto account_unknown_device_page(AccountPageFrame const& frame) -> Page
{
    auto page = Page{HtmlText{"Device not found"}};
    add_signed_in_as(page, frame);
    page.error(HtmlText{"Your account has no device with this ID."});
    add_footer(page, frame);
    return page;
}

auto account_password_page(AccountPageFrame const& frame, std::optional<HtmlText> const& error) -> Page
{
    auto page = Page{HtmlText{"Change your password"}};
    add_signed_in_as(page, frame);
    page.paragraph(HtmlText{"After the change every session of your account is signed out, in every application and on "
                            "every device, and so are these pages. Sign in again with the new password."});
    add_error(page, error);
    if (auto form = session_form(frame); form.has_value())
    {
        std::ignore = form->input(
            password_input(account_current_password_field, HtmlText{"Current password"}, HtmlName{"current-password"}));
        std::ignore =
            form->input(password_input(account_new_password_field, HtmlText{"New password"}, HtmlName{"new-password"}));
        std::ignore = form->input(password_input(account_new_password_confirm_field,
                                                 HtmlText{"Repeat the new password"}, HtmlName{"new-password"}));
        std::ignore =
            form->button(SubmitButton{action_field, account_post_change_password, HtmlText{"Change password"}});
        std::ignore = page.form(*form);
    }
    add_footer(page, frame);
    return page;
}

auto account_deactivate_page(AccountPageFrame const& frame, std::optional<HtmlText> const& error) -> Page
{
    auto page = Page{HtmlText{"Deactivate your account"}};
    add_signed_in_as(page, frame);
    page.paragraph(HtmlText{"Deactivation cannot be undone. Every session of your account is signed out, you can never "
                            "sign in again, and nobody can register your user ID again."});
    add_error(page, error);
    if (auto form = session_form(frame); form.has_value())
    {
        std::ignore =
            form->input(password_input(password_field, HtmlText{"Your password"}, HtmlName{"current-password"}));
        std::ignore =
            form->button(SubmitButton{action_field, account_post_deactivate, HtmlText{"Deactivate my account"}});
        std::ignore = page.form(*form);
    }
    add_footer(page, frame);
    return page;
}

auto account_cross_signing_reset_page(AccountPageFrame const& frame) -> Page
{
    auto page = Page{HtmlText{"Reset your encryption identity"}};
    add_signed_in_as(page, frame);
    page.paragraph(HtmlText{"Your application asked to replace your encryption identity (your cross-signing keys). If "
                            "you allow it, the people you talk to will see you as unverified until they verify you "
                            "again, and your other devices must be verified again."});
    page.paragraph(
        HtmlText{"Allow it only if you started the reset in your application. The permission lasts 10 minutes "
                 "and is used by one reset."});
    if (auto form = session_form(frame); form.has_value())
    {
        std::ignore = form->button(SubmitButton{action_field, account_post_approve_reset, HtmlText{"Allow the reset"}});
        std::ignore = page.form(*form);
    }
    add_footer(page, frame);
    return page;
}

auto account_result_page(AccountPageFrame const& frame, HtmlText title, HtmlText const& message) -> Page
{
    auto page = Page{std::move(title)};
    add_signed_in_as(page, frame);
    page.paragraph(message);
    add_footer(page, frame);
    return page;
}

auto account_signed_out_page(HtmlText title, HtmlText const& message, std::string_view account_url) -> Page
{
    auto page = Page{std::move(title)};
    page.paragraph(message);
    std::ignore = page.link(HtmlText{"Sign in"}, account_url);
    return page;
}

} // namespace merovingian::oauth
