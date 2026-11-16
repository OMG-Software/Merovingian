// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/AuthorizationPages.hpp"

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

    // `text` escaped, or `fallback` when HtmlText::escape refuses it (empty, too long, a control or bidirectional
    // formatting character): the raw value is never shown.
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

    // The pending identifier as the hidden field's value; nullopt when it cannot be shown, and the page then has no
    // form.
    [[nodiscard]] auto pending_value(std::string_view pending_id) -> std::optional<HtmlText>
    {
        return HtmlText::escape(pending_id);
    }

    auto add_messages(Page& page, AccountFormInput const& input) -> void
    {
        if (input.notice.has_value())
        {
            page.notice(*input.notice);
        }
        if (input.error.has_value())
        {
            page.error(*input.error);
        }
    }

    auto add_cannot_continue(Page& page) -> void
    {
        page.error(HtmlText{"This sign-in cannot continue. Return to the application and start again."});
    }

    // A form holding only the pending identifier and one button, such as the switch to the other form.
    auto add_switch_form(Page& page, HtmlText const& pending, HtmlName action, HtmlText label) -> void
    {
        auto form = PageForm{authorize_path};
        form.hidden(pending_field, pending);
        std::ignore = form.button(SubmitButton{action_field, action, std::move(label)});
        std::ignore = page.form(form);
    }

    // The username input, prefilled with `username` when it can be shown.
    [[nodiscard]] auto username_input(std::optional<std::string_view> username) -> TextInput
    {
        auto input = TextInput{username_field, HtmlText{"Username"}, HtmlName{"username"}};
        if (username.has_value())
        {
            input.value = HtmlText::escape(*username);
        }
        return input;
    }

    [[nodiscard]] auto password_input(HtmlName name, HtmlText label, HtmlName autocomplete) -> TextInput
    {
        auto input = TextInput{name, std::move(label), autocomplete};
        input.concealed = true;
        return input;
    }

    // Where the browser is sent next, as the consent page names it: the host of an `http` or `https` address, else the
    // private-use scheme (which names the application, since it is the reversed host of its client URI).
    [[nodiscard]] auto destination_of(ParsedUri const& target) -> HtmlText
    {
        auto const& scheme = target.scheme();
        auto const web = scheme == "https" || scheme == "http";
        if (web && target.has_authority())
        {
            return shown(target.host(), "an address that cannot be shown");
        }
        auto text = scheme;
        text.append(": (an application on your device)");
        return shown(text, "an address that cannot be shown");
    }

} // namespace

auto login_page(AccountFormInput const& input) -> Page
{
    auto page = Page{HtmlText{"Sign in"}};
    page.paragraph(
        sentence("Sign in with your account on ", input.server_name, ".", "Sign in with your account on this server."));
    add_messages(page, input);
    auto const pending = pending_value(input.pending_id);
    if (!pending.has_value())
    {
        add_cannot_continue(page);
        return page;
    }
    auto form = PageForm{authorize_path};
    form.hidden(pending_field, *pending);
    std::ignore = form.input(username_input(input.username));
    std::ignore = form.input(password_input(password_field, HtmlText{"Password"}, HtmlName{"current-password"}));
    std::ignore = form.button(SubmitButton{action_field, action_login, HtmlText{"Sign in"}});
    std::ignore = page.form(form);
    if (input.offer_other_form)
    {
        page.paragraph(HtmlText{"No account yet?"});
        add_switch_form(page, *pending, action_show_register, HtmlText{"Create an account"});
    }
    return page;
}

auto registration_page(AccountFormInput const& input) -> Page
{
    auto page = Page{HtmlText{"Create an account"}};
    page.paragraph(sentence("Create an account on ", input.server_name, ".", "Create an account on this server."));
    add_messages(page, input);
    auto const pending = pending_value(input.pending_id);
    if (!pending.has_value())
    {
        add_cannot_continue(page);
        return page;
    }
    auto form = PageForm{authorize_path};
    form.hidden(pending_field, *pending);
    std::ignore = form.input(username_input(input.username));
    std::ignore = form.input(password_input(password_field, HtmlText{"Password"}, HtmlName{"new-password"}));
    std::ignore =
        form.input(password_input(password_confirm_field, HtmlText{"Repeat the password"}, HtmlName{"new-password"}));
    if (input.registration_token_required)
    {
        std::ignore = form.input(TextInput{registration_token_field, HtmlText{"Registration token"}, HtmlName{"off"}});
    }
    std::ignore = form.button(SubmitButton{action_field, action_register, HtmlText{"Create account"}});
    std::ignore = page.form(form);
    if (input.offer_other_form)
    {
        page.paragraph(HtmlText{"Already have an account?"});
        add_switch_form(page, *pending, action_show_login, HtmlText{"Sign in instead"});
    }
    return page;
}

auto consent_page(ConsentPageInput const& input, ParsedUri const& redirect_target) -> Page
{
    auto page = Page{HtmlText{"Allow access to your account"}};
    auto const client_name = input.client_name.has_value() ? shown(*input.client_name, "An application with no name")
                                                           : HtmlText{"An application with no name"};
    auto const details = std::array{
        PageDetail{HtmlText{"Application"}, client_name},
        PageDetail{HtmlText{"Application website"}, shown(input.client_host, "an address that cannot be shown")},
        PageDetail{HtmlText{"After you answer, your browser goes to"}, destination_of(redirect_target)},
        PageDetail{HtmlText{"Account"}, shown(input.user_id, "an account that cannot be shown")},
        PageDetail{HtmlText{"Device ID"}, shown(input.device_id, "a device that cannot be shown")},
    };
    page.details(details);
    page.paragraph(HtmlText{"If you allow it, this application gets full access to your account: it can read and send "
                            "your messages, join and leave rooms and change your settings, as you can."});
    if (input.replaces_existing_device)
    {
        page.notice(HtmlText{"Your account already has a session with this device ID. Allowing access signs that "
                             "session out and replaces it."});
    }
    if (input.policy_uri.has_value())
    {
        std::ignore = page.link(HtmlText{"Privacy policy of the application"}, *input.policy_uri);
    }
    if (input.tos_uri.has_value())
    {
        std::ignore = page.link(HtmlText{"Terms of service of the application"}, *input.tos_uri);
    }
    auto const pending = pending_value(input.pending_id);
    if (!pending.has_value())
    {
        add_cannot_continue(page);
        return page;
    }
    auto form = PageForm{authorize_path};
    form.hidden(pending_field, *pending);
    std::ignore = form.button(SubmitButton{action_field, action_approve, HtmlText{"Allow"}});
    std::ignore = form.button(SubmitButton{action_field, action_deny, HtmlText{"Deny"}});
    std::ignore = page.form(form);
    return page;
}

auto error_page(HtmlText title, HtmlText const& message) -> Page
{
    auto page = Page{std::move(title)};
    page.error(message);
    return page;
}

} // namespace merovingian::oauth
