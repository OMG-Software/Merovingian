// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/AccountPage.hpp"

#include "merovingian/auth/AccountState.hpp"
#include "merovingian/auth/Identity.hpp"
#include "merovingian/core/CookieSameSite.hpp"
#include "merovingian/core/FormFields.hpp"
#include "merovingian/core/HostCookie.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AccountSession.hpp"
#include "merovingian/homeserver/AccountSessionStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientDeviceSessions.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/DeactivationAudit.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/homeserver/OAuthClientRegistration.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"
#include "merovingian/homeserver/OAuthPageResponse.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/PasswordLoginRequest.hpp"
#include "merovingian/homeserver/PasswordLoginVerification.hpp"
#include "merovingian/oauth/AccountDeviceRow.hpp"
#include "merovingian/oauth/AccountPageFrame.hpp"
#include "merovingian/oauth/AccountPages.hpp"
#include "merovingian/oauth/AccountSignInInput.hpp"
#include "merovingian/oauth/AuthorizationPages.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"
#include "merovingian/oauth/FormContentType.hpp"
#include "merovingian/oauth/FormPostOrigin.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/OAuthBaseUrl.hpp"
#include "merovingian/oauth/OAuthPaths.hpp"
#include "merovingian/oauth/Page.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    using Outcome = PasswordLoginVerification::Outcome;

    constexpr auto status_ok = std::uint16_t{200U};
    constexpr auto status_see_other = std::uint16_t{303U};
    constexpr auto status_bad_request = std::uint16_t{400U};
    constexpr auto status_unauthorized = std::uint16_t{401U};
    constexpr auto status_forbidden = std::uint16_t{403U};
    constexpr auto status_not_found = std::uint16_t{404U};
    constexpr auto status_too_many_requests = std::uint16_t{429U};
    constexpr auto status_server_error = std::uint16_t{500U};
    constexpr auto status_unavailable = std::uint16_t{503U};
    // The longest username read from the sign-in form: a user ID is at most 255 bytes, so no account has a longer one.
    constexpr auto max_sign_in_username_bytes = std::size_t{255U};

    auto log_account(std::string_view event, std::string_view user_id, observability::LogEventSeverity severity) -> void
    {
        auto fields = std::vector<observability::StructuredLogField>{};
        if (!user_id.empty())
        {
            fields.push_back({"user_id", std::string{user_id}, false});
        }
        observability::log_diagnostic("oauth", event, fields, severity);
    }

    // What every handler step works with: the runtime, the request and the address of the pages.
    struct AccountContext final
    {
        ClientServerRuntime& rt;
        RuntimeLock& guard;
        LocalHttpRequest const& request;
        oauth::OAuthBaseUrl const& base_url;
        std::string account_url{};
    };

    // A live session found from the request's cookie: its secret (to end it), its user and its form token.
    struct SignedIn final
    {
        std::string secret{};
        AccountSession session{};
        std::string form_token{};
    };

    // The `Set-Cookie` that deletes the session cookie, or nothing when it cannot be built (a fixed, valid name: only a
    // defect refuses it).
    [[nodiscard]] auto with_cookie_deleted(LocalHttpResponse response) -> LocalHttpResponse
    {
        auto deletion = core::host_cookie_deletion(account_cookie_name, core::CookieSameSite::strict);
        if (auto const* const value = std::get_if<std::string>(&deletion); value != nullptr)
        {
            response.headers.emplace_back("Set-Cookie", *value);
        }
        return response;
    }

    [[nodiscard]] auto form_refused(oauth::HtmlText const& message, std::uint16_t status = status_bad_request)
        -> LocalHttpResponse
    {
        return oauth_error_page_response(status, oauth::HtmlText{"Form refused"}, message);
    }

    [[nodiscard]] auto server_name_of(AccountContext const& context) -> std::string_view
    {
        return context.rt.homeserver.config.server().server_name;
    }

    [[nodiscard]] auto frame_of(AccountContext const& context, SignedIn const& signed_in) -> oauth::AccountPageFrame
    {
        return oauth::AccountPageFrame{server_name_of(context), signed_in.session.user_id, signed_in.form_token,
                                       context.account_url};
    }

    // The action and device the browser asked for, each only when valid: `action` one of the six spec actions, and
    // `device_id` only with a device action and only one `auth::device_id_is_valid` accepts (spec: "Actions which don't
    // support the device ID will ignore it").
    struct RequestedPage final
    {
        std::optional<std::string_view> action{};
        std::optional<std::string> device_id{};
    };

    [[nodiscard]] auto requested_page(std::optional<std::string_view> action, std::optional<std::string_view> device_id)
        -> RequestedPage
    {
        auto page = RequestedPage{};
        page.action = oauth::account_management_action(action);
        if (page.action.has_value() && oauth::account_action_takes_device(*page.action) && device_id.has_value() &&
            auth::device_id_is_valid(*device_id))
        {
            page.device_id = std::string{*device_id};
        }
        return page;
    }

    // The live session the request's cookie names, its user still allowed to sign in. A session whose user no longer
    // may (deactivated, locked, gone) is ended here.
    [[nodiscard]] auto find_signed_in(AccountContext const& context) -> std::optional<SignedIn>
    {
        auto secret = request_secret_cookie(context.request, account_cookie_name);
        if (!secret.has_value())
        {
            return std::nullopt;
        }
        auto& runtime = context.rt.homeserver;
        auto const now_ms = oauth_wall_clock_ms();
        auto session = runtime.account_sessions.find(*secret, now_ms);
        if (!session.has_value())
        {
            return std::nullopt;
        }
        if (account_sign_in_gate(runtime, session->user_id, {}) != Outcome::verified)
        {
            std::ignore = runtime.account_sessions.end(*secret, now_ms);
            return std::nullopt;
        }
        auto form_token = AccountSessionStore::form_token(*secret);
        if (!form_token.has_value())
        {
            return std::nullopt;
        }
        return SignedIn{std::move(*secret), std::move(*session), std::move(*form_token)};
    }

    // Whether the session `signed_in` names is still live and its user may still sign in: asked again after any call
    // that released runtime.mutex.
    [[nodiscard]] auto still_signed_in(AccountContext const& context, SignedIn const& signed_in) -> bool
    {
        auto& runtime = context.rt.homeserver;
        auto const now_ms = oauth_wall_clock_ms();
        auto const session = runtime.account_sessions.find(signed_in.secret, now_ms);
        if (!session.has_value() || session->user_id != signed_in.session.user_id)
        {
            return false;
        }
        if (account_sign_in_gate(runtime, session->user_id, {}) != Outcome::verified)
        {
            std::ignore = runtime.account_sessions.end(signed_in.secret, now_ms);
            return false;
        }
        return true;
    }

    [[nodiscard]] auto sign_in_page_response(AccountContext const& context, std::uint16_t status,
                                             RequestedPage const& requested, std::optional<std::string_view> username,
                                             std::optional<oauth::HtmlText> error,
                                             std::optional<oauth::HtmlText> notice = std::nullopt) -> LocalHttpResponse
    {
        auto input = oauth::AccountSignInInput{};
        input.server_name = server_name_of(context);
        input.next_action = requested.action;
        if (requested.device_id.has_value())
        {
            input.next_device_id = *requested.device_id;
        }
        // A username is shown again only when it could be an account's: never text that is not a user ID or localpart.
        if (username.has_value() && (auth::localpart_is_valid_new(*username) || auth::user_id_is_valid(*username)))
        {
            input.username = *username;
        }
        input.error = std::move(error);
        input.notice = std::move(notice);
        return oauth_plain_page(status, oauth::account_sign_in_page(input));
    }

    // The page with no session: a form that needs one was sent without, or the session ended.
    [[nodiscard]] auto signed_out_response(AccountContext const& context, std::uint16_t status, oauth::HtmlText title,
                                           oauth::HtmlText const& message) -> LocalHttpResponse
    {
        return with_cookie_deleted(
            oauth_plain_page(status, oauth::account_signed_out_page(std::move(title), message, context.account_url)));
    }

    [[nodiscard]] auto session_ended_response(AccountContext const& context) -> LocalHttpResponse
    {
        return signed_out_response(
            context, status_forbidden, oauth::HtmlText{"Signed out"},
            oauth::HtmlText{"Your session on these pages has ended. Sign in again to continue."});
    }

    // The devices of the user, through the per-user device index, with the registered client name of each OAuth
    // device. At most the per-user device cap; a client is read once however many of its devices there are.
    struct OwnedDeviceRow final
    {
        std::string device_id{};
        std::string display_name{};
        bool oauth_session{false};
        std::optional<std::string> client_name{};
    };

    [[nodiscard]] auto owned_row(HomeserverRuntime const& runtime, database::PersistentDevice const& device,
                                 std::map<std::string, std::optional<std::string>, std::less<>>& client_names)
        -> OwnedDeviceRow
    {
        auto row = OwnedDeviceRow{device.device_id, device.display_name, false, std::nullopt};
        auto const* const oauth_session =
            database::find_oauth_session(runtime.database.persistent_store, device.user_id, device.device_id);
        if (oauth_session == nullptr)
        {
            return row;
        }
        row.oauth_session = true;
        auto known = client_names.find(oauth_session->client_id);
        if (known == client_names.end())
        {
            auto const client = find_registered_oauth_client(runtime, oauth_session->client_id);
            auto name = client.has_value() ? client->client_name() : std::optional<std::string>{};
            known = client_names.emplace(oauth_session->client_id, std::move(name)).first;
        }
        row.client_name = known->second;
        return row;
    }

    [[nodiscard]] auto view_of(OwnedDeviceRow const& row) -> oauth::AccountDeviceRow
    {
        auto view = oauth::AccountDeviceRow{row.device_id, row.display_name, row.oauth_session, std::nullopt};
        if (row.client_name.has_value())
        {
            view.client_name = *row.client_name;
        }
        return view;
    }

    [[nodiscard]] auto user_devices(HomeserverRuntime const& runtime, std::string_view user_id)
        -> std::vector<OwnedDeviceRow>
    {
        auto rows = std::vector<OwnedDeviceRow>{};
        auto client_names = std::map<std::string, std::optional<std::string>, std::less<>>{};
        database::for_each_user_device(runtime.database.persistent_store, user_id,
                                       [&](database::PersistentDevice const& device) {
                                           rows.push_back(owned_row(runtime, device, client_names));
                                           return true;
                                       });
        return rows;
    }

    // One device of the user, or nullopt when the user holds no device with this ID (whoever else may).
    [[nodiscard]] auto user_device(HomeserverRuntime const& runtime, std::string_view user_id,
                                   std::string_view device_id) -> std::optional<OwnedDeviceRow>
    {
        auto found = std::optional<OwnedDeviceRow>{};
        auto client_names = std::map<std::string, std::optional<std::string>, std::less<>>{};
        database::for_each_user_device(runtime.database.persistent_store, user_id,
                                       [&](database::PersistentDevice const& device) {
                                           if (device.device_id != device_id)
                                           {
                                               return true;
                                           }
                                           found = owned_row(runtime, device, client_names);
                                           return false;
                                       });
        return found;
    }

    [[nodiscard]] auto unknown_device_response(AccountContext const& context, SignedIn const& signed_in)
        -> LocalHttpResponse
    {
        return oauth_plain_page(status_not_found, oauth::account_unknown_device_page(frame_of(context, signed_in)));
    }

    // The page `requested` names, for a signed-in user.
    [[nodiscard]] auto action_page(AccountContext const& context, SignedIn const& signed_in,
                                   RequestedPage const& requested) -> LocalHttpResponse
    {
        auto const& runtime = context.rt.homeserver;
        auto const frame = frame_of(context, signed_in);
        auto const& user_id = signed_in.session.user_id;
        auto const action = requested.action.value_or(oauth::account_action_profile);
        if (action == oauth::account_action_devices_list ||
            (oauth::account_action_takes_device(action) && !requested.device_id.has_value()))
        {
            auto const rows = user_devices(runtime, user_id);
            auto views = std::vector<oauth::AccountDeviceRow>{};
            views.reserve(rows.size());
            for (auto const& row : rows)
            {
                views.push_back(view_of(row));
            }
            return oauth_plain_page(status_ok, oauth::account_devices_page(frame, views));
        }
        if (oauth::account_action_takes_device(action))
        {
            auto const device = user_device(runtime, user_id, *requested.device_id);
            if (!device.has_value())
            {
                return unknown_device_response(context, signed_in);
            }
            auto const view = view_of(*device);
            return oauth_plain_page(status_ok, action == oauth::account_action_device_delete
                                                   ? oauth::account_device_delete_page(frame, view)
                                                   : oauth::account_device_page(frame, view));
        }
        if (action == oauth::account_action_account_deactivate)
        {
            return oauth_plain_page(status_ok, oauth::account_deactivate_page(frame, std::nullopt));
        }
        if (action == oauth::account_action_cross_signing_reset)
        {
            return oauth_plain_page(status_ok, oauth::account_cross_signing_reset_page(frame));
        }
        auto const profile = database::find_profile(runtime.database.persistent_store, user_id);
        auto display_name = std::optional<std::string_view>{};
        if (profile.has_value())
        {
            display_name = profile->displayname;
        }
        return oauth_plain_page(status_ok, oauth::account_overview_page(frame, display_name));
    }

    [[nodiscard]] auto handle_get(AccountContext const& context) -> LocalHttpResponse
    {
        auto parsed = core::FormFields::parse(request_target_query(context.request.target));
        auto const* const fields = std::get_if<core::FormFields>(&parsed);
        // An unreadable query (a parameter sent twice, a bad escape) asks for nothing: the overview.
        auto const requested =
            fields == nullptr ? RequestedPage{} : requested_page(fields->find("action"), fields->find("device_id"));
        auto const signed_in = find_signed_in(context);
        if (!signed_in.has_value())
        {
            auto response = sign_in_page_response(context, status_ok, requested, std::nullopt, std::nullopt);
            // A cookie that names no live session is deleted, so the browser stops sending it.
            if (request_secret_cookie(context.request, account_cookie_name).has_value())
            {
                response = with_cookie_deleted(std::move(response));
            }
            return response;
        }
        return action_page(context, *signed_in, requested);
    }

    // The outcome of checking a password a form carries, as a page when it failed.
    struct PasswordCheck final
    {
        bool verified{false};
        Outcome outcome{Outcome::invalid_login};
        std::uint32_t retry_after_seconds{0U};
    };

    // Verifies `password` for `user_id` as POST /login does, with its throttle (per account and client source).
    // Releases runtime.mutex around Argon2id: the caller trusts nothing it read before.
    [[nodiscard]] auto check_password(AccountContext const& context, std::string_view user_id,
                                      std::string_view password) -> PasswordCheck
    {
        auto& runtime = context.rt.homeserver;
        auto const client_key = rate_limit_client_key(context.request, runtime.config.server());
        auto const verified = verify_password_login(runtime, PasswordLoginRequest{user_id, password, client_key, {}});
        auto check = PasswordCheck{};
        check.outcome = verified.outcome;
        check.verified = verified.outcome == Outcome::verified && verified.user_id == user_id;
        if (verified.outcome == Outcome::throttled || verified.outcome == Outcome::busy)
        {
            check.retry_after_seconds = retry_after_seconds(verified.retry_after_ms);
        }
        return check;
    }

    // The message, status and headers of a failed password check on a signed-in form.
    struct PasswordFailure final
    {
        std::uint16_t status{status_unauthorized};
        // A default member initialiser is not constant-evaluated: the HtmlLiteral check runs at run time here, so the
        // text holds nothing that would need escaping.
        oauth::HtmlText message{"That is not the password of this account."};
        std::optional<std::uint32_t> retry_after_seconds{};
    };

    [[nodiscard]] auto password_failure(PasswordCheck const& check) -> PasswordFailure
    {
        switch (check.outcome)
        {
        case Outcome::throttled: {
            auto text = "Too many failed password attempts for this account. Try again in " +
                        std::to_string(check.retry_after_seconds) + " seconds.";
            auto message = oauth::HtmlText::escape(text);
            return {status_too_many_requests,
                    message.has_value() ? std::move(*message)
                                        : oauth::HtmlText{"Too many failed password attempts. Try again later."},
                    check.retry_after_seconds};
        }
        case Outcome::busy:
            return {status_unavailable, oauth::HtmlText{"The server is busy. Try again in a moment."},
                    check.retry_after_seconds};
        case Outcome::verified:
        case Outcome::invalid_login:
        case Outcome::account_deactivated:
            break;
        }
        return {};
    }

    [[nodiscard]] auto with_retry_after(LocalHttpResponse response, std::optional<std::uint32_t> seconds)
        -> LocalHttpResponse
    {
        if (seconds.has_value())
        {
            response.headers.emplace_back("Retry-After", std::to_string(*seconds));
        }
        return response;
    }

    [[nodiscard]] auto handle_sign_in(AccountContext const& context, core::FormFields const& fields)
        -> LocalHttpResponse
    {
        auto& runtime = context.rt.homeserver;
        auto const requested = requested_page(fields.find(oauth::account_next_action_field.view()),
                                              fields.find(oauth::account_next_device_field.view()));
        auto const username = fields.find(oauth::username_field.view());
        auto const password = fields.find(oauth::password_field.view());
        if (!username.has_value() || username->empty() || !password.has_value() || password->empty())
        {
            return sign_in_page_response(context, status_bad_request, requested, username,
                                         oauth::HtmlText{"Enter your username and password."});
        }
        auto const invalid_login = [&]() {
            return sign_in_page_response(
                context, status_unauthorized, requested, username,
                oauth::HtmlText{"That username and password do not match an account on this server."});
        };
        if (username->size() > max_sign_in_username_bytes)
        {
            return invalid_login();
        }
        auto const user_id = login_identifier_user_id(server_name_of(context), *username);
        // Releases runtime.mutex around Argon2id.
        auto const check = check_password(context, user_id, *password);
        switch (check.outcome)
        {
        case Outcome::verified:
            break;
        case Outcome::invalid_login:
            return invalid_login();
        case Outcome::account_deactivated:
            return sign_in_page_response(
                context, status_forbidden, requested, username,
                oauth::HtmlText{"This account has been deactivated and can no longer sign in."});
        case Outcome::throttled:
        case Outcome::busy: {
            auto failure = password_failure(check);
            return with_retry_after(
                sign_in_page_response(context, failure.status, requested, username, std::move(failure.message)),
                failure.retry_after_seconds);
        }
        }
        if (!check.verified)
        {
            return invalid_login();
        }
        auto const now_ms = oauth_wall_clock_ms();
        // A session the browser already held ends: a sign-in always starts a session of its own.
        if (auto const previous = request_secret_cookie(context.request, account_cookie_name); previous.has_value())
        {
            std::ignore = runtime.account_sessions.end(*previous, now_ms);
        }
        auto const busy = [&]() {
            return with_retry_after(
                sign_in_page_response(context, status_unavailable, requested, username,
                                      oauth::HtmlText{"The server cannot sign you in now. Try again in a moment."}),
                1U);
        };
        auto created = runtime.account_sessions.create(user_id, now_ms);
        auto const* const secret = std::get_if<std::string>(&created);
        if (secret == nullptr)
        {
            return busy();
        }
        auto cookie = core::host_cookie(account_cookie_name, *secret, core::CookieSameSite::strict,
                                        account_cookie_max_age_seconds);
        auto const* const set_cookie = std::get_if<std::string>(&cookie);
        if (set_cookie == nullptr)
        {
            std::ignore = runtime.account_sessions.end(*secret, now_ms);
            return busy();
        }
        log_account("account.page.signed_in", user_id, observability::LogEventSeverity::info);
        auto location = context.account_url;
        if (requested.action.has_value())
        {
            location = oauth::account_action_address(
                context.account_url, *requested.action,
                requested.device_id.has_value() ? std::optional<std::string_view>{*requested.device_id} : std::nullopt);
        }
        auto response = LocalHttpResponse{};
        response.status = status_see_other;
        response.headers = {
            {"Location",        std::move(location)},
            {"Cache-Control",   "no-store"         },
            {"Referrer-Policy", "same-origin"      },
            {"Set-Cookie",      *set_cookie        },
        };
        response.page = true;
        return response;
    }

    [[nodiscard]] auto result_page(AccountContext const& context, SignedIn const& signed_in, std::uint16_t status,
                                   oauth::HtmlText title, oauth::HtmlText const& message) -> LocalHttpResponse
    {
        return oauth_plain_page(status,
                                oauth::account_result_page(frame_of(context, signed_in), std::move(title), message));
    }

    [[nodiscard]] auto handle_delete_device(AccountContext const& context, SignedIn const& signed_in,
                                            core::FormFields const& fields) -> LocalHttpResponse
    {
        auto const device_id = fields.find(oauth::account_device_field.view());
        if (!device_id.has_value() || !auth::device_id_is_valid(*device_id))
        {
            return unknown_device_response(context, signed_in);
        }
        // The client API's DELETE /devices/{deviceId}, after its authentication: a device that is not this user's is
        // 404 whoever holds it, and the same page as a device that never existed.
        auto const result = delete_device_and_announce(context.rt, signed_in.session.user_id, *device_id);
        if (!result.ok)
        {
            if (result.status == status_not_found || result.status == status_bad_request)
            {
                return unknown_device_response(context, signed_in);
            }
            return result_page(context, signed_in, status_server_error, oauth::HtmlText{"Device not signed out"},
                               oauth::HtmlText{"The device could not be signed out. Try again later."});
        }
        log_account("account.page.device_deleted", signed_in.session.user_id, observability::LogEventSeverity::info);
        return result_page(context, signed_in, status_ok, oauth::HtmlText{"Device signed out"},
                           oauth::HtmlText{"The device is signed out and removed from your account."});
    }

    [[nodiscard]] auto password_page(AccountContext const& context, SignedIn const& signed_in, std::uint16_t status,
                                     std::optional<oauth::HtmlText> error) -> LocalHttpResponse
    {
        return oauth_plain_page(status, oauth::account_password_page(frame_of(context, signed_in), error));
    }

    // The fixed message and status for a refused password change.
    [[nodiscard]] auto password_change_refusal(OperationResult const& result)
        -> std::pair<std::uint16_t, oauth::HtmlText>
    {
        if (result.errcode == "M_WEAK_PASSWORD")
        {
            return {status_bad_request,
                    oauth::HtmlText{"This password is too weak. Choose a longer one that is harder to guess."}};
        }
        if (result.status == status_too_many_requests)
        {
            return {status_unavailable, oauth::HtmlText{"The server is busy. Try again in a moment."}};
        }
        if (result.status == status_forbidden)
        {
            return {status_forbidden,
                    oauth::HtmlText{"The password was changed elsewhere meanwhile. Sign in again and retry."}};
        }
        return {status_server_error, oauth::HtmlText{"The password could not be changed. Try again later."}};
    }

    [[nodiscard]] auto handle_change_password(AccountContext const& context, SignedIn const& signed_in,
                                              core::FormFields const& fields) -> LocalHttpResponse
    {
        auto& runtime = context.rt.homeserver;
        auto const& user_id = signed_in.session.user_id;
        // The client API refuses POST /account/password to a suspended account (its allowlist does not hold it).
        if (account_state_for_user(runtime, user_id) == auth::AccountState::suspended)
        {
            return result_page(context, signed_in, status_forbidden, oauth::HtmlText{"Password not changed"},
                               oauth::HtmlText{"This account is suspended, so its password cannot be changed."});
        }
        auto const current = fields.find(oauth::account_current_password_field.view());
        auto const replacement = fields.find(oauth::account_new_password_field.view());
        auto const confirmation = fields.find(oauth::account_new_password_confirm_field.view());
        if (!current.has_value() || current->empty() || !replacement.has_value() || replacement->empty() ||
            !confirmation.has_value())
        {
            return password_page(context, signed_in, status_bad_request, oauth::HtmlText{"Fill in every field."});
        }
        if (*replacement != *confirmation)
        {
            return password_page(context, signed_in, status_bad_request,
                                 oauth::HtmlText{"The two new passwords do not match."});
        }
        // Releases runtime.mutex around Argon2id: the session is found again below.
        auto const check = check_password(context, user_id, *current);
        if (!still_signed_in(context, signed_in))
        {
            return session_ended_response(context);
        }
        if (!check.verified)
        {
            auto failure = password_failure(check);
            return with_retry_after(password_page(context, signed_in, failure.status, std::move(failure.message)),
                                    failure.retry_after_seconds);
        }
        // The core of the password reset: no device is kept, so every session of the account ends, these pages
        // included (ADR-0798). Releases runtime.mutex around the hash.
        auto const result = change_password_on_account_page(runtime, user_id, *replacement);
        if (!result.ok)
        {
            if (!still_signed_in(context, signed_in))
            {
                return session_ended_response(context);
            }
            auto [status, message] = password_change_refusal(result);
            return password_page(context, signed_in, status, std::move(message));
        }
        // As POST /account/password with logout_devices does: no login token outlives the change.
        context.rt.login_tokens.erase_user(user_id);
        log_account("account.page.password_changed", user_id, observability::LogEventSeverity::info);
        return signed_out_response(context, status_ok, oauth::HtmlText{"Password changed"},
                                   oauth::HtmlText{"Your password is changed and every session of your account is "
                                                   "signed out. Sign in again with the new password."});
    }

    [[nodiscard]] auto deactivate_page(AccountContext const& context, SignedIn const& signed_in, std::uint16_t status,
                                       std::optional<oauth::HtmlText> error) -> LocalHttpResponse
    {
        return oauth_plain_page(status, oauth::account_deactivate_page(frame_of(context, signed_in), error));
    }

    [[nodiscard]] auto handle_deactivate(AccountContext const& context, SignedIn const& signed_in,
                                         core::FormFields const& fields) -> LocalHttpResponse
    {
        auto& runtime = context.rt.homeserver;
        auto const user_id = signed_in.session.user_id;
        auto const password = fields.find(oauth::password_field.view());
        if (!password.has_value() || password->empty())
        {
            return deactivate_page(context, signed_in, status_bad_request, oauth::HtmlText{"Enter your password."});
        }
        // Releases runtime.mutex around Argon2id: the session is found again below.
        auto const check = check_password(context, user_id, *password);
        if (!still_signed_in(context, signed_in))
        {
            return session_ended_response(context);
        }
        if (!check.verified)
        {
            auto failure = password_failure(check);
            return with_retry_after(deactivate_page(context, signed_in, failure.status, std::move(failure.message)),
                                    failure.retry_after_seconds);
        }
        // The client API's deactivation and what its handler does after it: every token, pusher and account-page
        // session goes, the login tokens, and every 3PID bound at an identity server is unbound (releasing
        // runtime.mutex for each call). Devices stay, as POST /account/deactivate leaves them.
        auto const result = deactivate_user_account(
            runtime, user_id, DeactivationAudit{user_id, user_id, "deactivated on the account page"});
        if (!result.ok)
        {
            return result_page(context, signed_in, status_server_error, oauth::HtmlText{"Account not deactivated"},
                               oauth::HtmlText{"The account could not be deactivated. Try again later."});
        }
        std::ignore = finish_account_deactivation(context.rt, context.guard, user_id, std::nullopt);
        log_account("account.page.deactivated", user_id, observability::LogEventSeverity::info);
        return signed_out_response(
            context, status_ok, oauth::HtmlText{"Account deactivated"},
            oauth::HtmlText{"Your account is deactivated and every session of it is signed out."});
    }

    [[nodiscard]] auto handle_approve_reset(AccountContext const& context, SignedIn const& signed_in)
        -> LocalHttpResponse
    {
        auto& runtime = context.rt.homeserver;
        auto const& user_id = signed_in.session.user_id;
        if (!runtime.cross_signing_reset_approvals.approve(user_id, oauth_wall_clock_ms()))
        {
            return with_retry_after(result_page(context, signed_in, status_unavailable,
                                                oauth::HtmlText{"Reset not allowed"},
                                                oauth::HtmlText{"The server cannot record this now. Try again later."}),
                                    1U);
        }
        append_local_audit(runtime.database, observability::AuditCategory::auth, "cross_signing.reset_approved",
                           user_id, user_id, "account page");
        log_account("account.page.cross_signing_reset_approved", user_id, observability::LogEventSeverity::info);
        return result_page(context, signed_in, status_ok, oauth::HtmlText{"Reset allowed"},
                           oauth::HtmlText{"Return to your application to finish the reset. The permission lasts 10 "
                                           "minutes and is used by one reset."});
    }

    [[nodiscard]] auto handle_post(AccountContext const& context) -> LocalHttpResponse
    {
        // Before anything is read: another site's post is refused whatever it carries (ADR-0784, ADR-0796).
        if (!oauth::form_post_origin_is_accepted(context.base_url, single_request_header(context.request, "Origin"),
                                                 single_request_header(context.request, "Sec-Fetch-Site")))
        {
            log_account("account.page.forbidden_origin", {}, observability::LogEventSeverity::debug);
            return form_refused(oauth::HtmlText{"This form was not sent from a page of this server."},
                                status_forbidden);
        }
        auto const content_type = single_request_header(context.request, "Content-Type");
        if (!content_type.has_value() || !oauth::page_form_content_type_is_accepted(*content_type))
        {
            return form_refused(oauth::HtmlText{"This form could not be read."});
        }
        auto parsed = core::FormFields::parse(context.request.body);
        auto const* const fields = std::get_if<core::FormFields>(&parsed);
        if (fields == nullptr)
        {
            return form_refused(oauth::HtmlText{"This form could not be read."});
        }
        auto const action = fields->find(oauth::action_field.view()).value_or(std::string_view{});
        if (action == oauth::account_post_sign_in.view())
        {
            return handle_sign_in(context, *fields);
        }
        // Every other form needs the session and its form token, which is not the cookie and is bound to it.
        auto const signed_in = find_signed_in(context);
        if (!signed_in.has_value())
        {
            return session_ended_response(context);
        }
        auto const form_token = fields->find(oauth::account_form_token_field.view());
        if (!form_token.has_value() || !AccountSessionStore::form_token_matches(signed_in->secret, *form_token))
        {
            return form_refused(oauth::HtmlText{"This form does not belong to your session. Reload the page and "
                                                "try again."},
                                status_forbidden);
        }
        if (action == oauth::account_post_sign_out.view())
        {
            std::ignore = context.rt.homeserver.account_sessions.end(signed_in->secret, oauth_wall_clock_ms());
            log_account("account.page.signed_out", signed_in->session.user_id, observability::LogEventSeverity::info);
            return signed_out_response(context, status_ok, oauth::HtmlText{"Signed out"},
                                       oauth::HtmlText{"You have signed out of these pages."});
        }
        if (action == oauth::account_post_show_password.view())
        {
            return password_page(context, *signed_in, status_ok, std::nullopt);
        }
        if (action == oauth::account_post_change_password.view())
        {
            return handle_change_password(context, *signed_in, *fields);
        }
        if (action == oauth::account_post_delete_device.view())
        {
            return handle_delete_device(context, *signed_in, *fields);
        }
        if (action == oauth::account_post_deactivate.view())
        {
            return handle_deactivate(context, *signed_in, *fields);
        }
        if (action == oauth::account_post_approve_reset.view())
        {
            return handle_approve_reset(context, *signed_in);
        }
        return form_refused(oauth::HtmlText{"This form asked for something this page does not do."});
    }

} // namespace

auto handle_account_page(ClientServerRuntime& rt, RuntimeLock& guard, LocalHttpRequest const& request)
    -> LocalHttpResponse
{
    auto base = oauth::OAuthBaseUrl::read(rt.homeserver.config.server().public_baseurl);
    auto const* const base_url = std::get_if<oauth::OAuthBaseUrl>(&base);
    if (base_url == nullptr)
    {
        return oauth_error_page_response(status_server_error, oauth::HtmlText{"Account pages are not available"},
                                         oauth::HtmlText{"This server is not configured for its account pages."});
    }
    auto const context = AccountContext{rt, guard, request, *base_url, base_url->url(oauth::account_path)};
    if (request.method == "POST")
    {
        return handle_post(context);
    }
    return handle_get(context);
}

} // namespace merovingian::homeserver
