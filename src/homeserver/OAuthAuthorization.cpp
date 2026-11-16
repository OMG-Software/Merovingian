// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthAuthorization.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/core/CookieSameSite.hpp"
#include "merovingian/core/Error.hpp"
#include "merovingian/core/FormFields.hpp"
#include "merovingian/core/HostCookie.hpp"
#include "merovingian/core/RequestCookies.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AccountCreationRequest.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/AuthorizationCodeStore.hpp"
#include "merovingian/homeserver/AuthorizationGrant.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/homeserver/OAuthClientRegistration.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"
#include "merovingian/homeserver/OAuthSecret.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/PasswordLoginRequest.hpp"
#include "merovingian/homeserver/PasswordLoginVerification.hpp"
#include "merovingian/homeserver/PendingAuthorisation.hpp"
#include "merovingian/homeserver/PendingAuthorisationStore.hpp"
#include "merovingian/homeserver/RequestHeaders.hpp"
#include "merovingian/oauth/AccountFormInput.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/AuthorizationPages.hpp"
#include "merovingian/oauth/AuthorizationRedirect.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"
#include "merovingian/oauth/ConsentPageInput.hpp"
#include "merovingian/oauth/FormPostOrigin.hpp"
#include "merovingian/oauth/GrantedScope.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/OAuthBaseUrl.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"
#include "merovingian/oauth/Page.hpp"
#include "merovingian/oauth/PageHeaders.hpp"
#include "merovingian/oauth/ParsedUri.hpp"
#include "merovingian/oauth/Pkce.hpp"
#include "merovingian/oauth/RedirectUriRules.hpp"
#include "merovingian/oauth/ResponseMode.hpp"
#include "merovingian/oauth/ScopeParser.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    using Outcome = PasswordLoginVerification::Outcome;

    constexpr auto status_ok = std::uint16_t{200U};
    constexpr auto status_found = std::uint16_t{302U};
    constexpr auto status_see_other = std::uint16_t{303U};
    constexpr auto status_bad_request = std::uint16_t{400U};
    constexpr auto status_unauthorized = std::uint16_t{401U};
    constexpr auto status_forbidden = std::uint16_t{403U};
    constexpr auto status_too_many_requests = std::uint16_t{429U};
    constexpr auto status_server_error = std::uint16_t{500U};
    constexpr auto status_unavailable = std::uint16_t{503U};
    // The longest username read from the login form: a user ID is at most 255 bytes, so no account has a longer one.
    constexpr auto max_login_username_bytes = std::size_t{255U};
    // A browser cookie value as make_oauth_secret mints it: 64 lower-case hex digits.
    constexpr auto browser_token_chars = std::size_t{oauth_secret_bytes * 2U};

    [[nodiscard]] auto application_type_name(oauth::ApplicationType type) noexcept -> std::string_view
    {
        return type == oauth::ApplicationType::native ? "native" : "web";
    }

    auto log_oauth(std::string_view event, std::vector<observability::StructuredLogField> fields,
                   observability::LogEventSeverity severity) -> void
    {
        observability::log_diagnostic("oauth", event, std::move(fields), severity);
    }

    // Logs a refused authorisation request: the client ID only once the client is known, and the wire error code.
    // Never the query, the state, the challenge or a value the client chose.
    auto log_refused(std::string_view client_id, std::string_view error_code) -> void
    {
        auto fields = std::vector<observability::StructuredLogField>{
            {"error", std::string{error_code}, false}
        };
        if (!client_id.empty())
        {
            fields.push_back({"client_id", std::string{client_id}, false});
        }
        log_oauth("oauth.authorization.refused", std::move(fields), observability::LogEventSeverity::debug);
    }

    // A page answer: the rendered page with the page headers (ADR-0772, ADR-0784) and the page mark (ADR-0785).
    [[nodiscard]] auto page_response(std::uint16_t status, oauth::Page const& page,
                                     std::vector<std::pair<std::string, std::string>> headers) -> LocalHttpResponse
    {
        auto response = LocalHttpResponse{};
        response.status = status;
        response.body = page.render();
        response.headers = std::move(headers);
        response.page = true;
        return response;
    }

    [[nodiscard]] auto plain_page(std::uint16_t status, oauth::Page const& page) -> LocalHttpResponse
    {
        return page_response(status, page, oauth::page_headers());
    }

    [[nodiscard]] auto error_page_response(std::uint16_t status, oauth::HtmlText title, oauth::HtmlText const& message)
        -> LocalHttpResponse
    {
        return plain_page(status, oauth::error_page(std::move(title), message));
    }

    // Step 1 of the request: nothing is redirected, because no address has been validated.
    [[nodiscard]] auto bad_request_page(oauth::HtmlText const& message) -> LocalHttpResponse
    {
        return error_page_response(status_bad_request, oauth::HtmlText{"This sign-in request cannot be used"}, message);
    }

    // The answer to a form post whose pending authorisation is gone, never was, or is bound to another browser. The
    // server no longer holds a validated address for it, so the user is sent back to the application by hand.
    [[nodiscard]] auto expired_page() -> LocalHttpResponse
    {
        return error_page_response(status_bad_request, oauth::HtmlText{"Sign-in expired"},
                                   oauth::HtmlText{"This sign-in has expired or was already finished. Return to the "
                                                   "application and start again."});
    }

    // A redirect to the client: the redirect URI the request gave, matched against the registration, with the answer in
    // the query or the fragment. `no-store` so no cache keeps a code, and `no-referrer` so the authorisation request's
    // address is not sent on as the Referer of the client's page.
    [[nodiscard]] auto redirect_response(std::uint16_t status, oauth::ParsedUri const& target, oauth::ResponseMode mode,
                                         std::span<oauth::RedirectParameter const> parameters) -> LocalHttpResponse
    {
        auto response = LocalHttpResponse{};
        response.status = status;
        response.headers = {
            {"Location", oauth::authorization_redirect_address(target, mode, parameters)},
            {"Cache-Control", "no-store"},
            {"Referrer-Policy", "no-referrer"},
        };
        response.page = true;
        return response;
    }

    // An error answer redirected to the client: `error`, the fixed `error_description`, and `state` when there is one.
    [[nodiscard]] auto error_redirect(std::uint16_t status, oauth::ParsedUri const& target, oauth::ResponseMode mode,
                                      std::string_view error_code, std::string_view description, std::string_view state)
        -> LocalHttpResponse
    {
        auto parameters = std::vector<oauth::RedirectParameter>{
            {"error",             error_code },
            {"error_description", description},
        };
        if (!state.empty())
        {
            parameters.emplace_back("state", state);
        }
        return redirect_response(status, target, mode, parameters);
    }

    // The query of a request target, without the `?`; empty when there is none.
    [[nodiscard]] auto target_query(std::string_view target) noexcept -> std::string_view
    {
        auto const at = target.find('?');
        return at == std::string_view::npos ? std::string_view{} : target.substr(at + 1U);
    }

    // The one value of header `name`, or nullopt when it is absent or sent more than once (a repeated `Origin`,
    // `Sec-Fetch-Site` or `Cookie` is treated as absent, never resolved).
    [[nodiscard]] auto single_header(LocalHttpRequest const& request, std::string_view name)
        -> std::optional<std::string_view>
    {
        auto const values = request_header_values(request, name);
        if (values.size() != 1U)
        {
            return std::nullopt;
        }
        return values.front();
    }

    [[nodiscard]] auto is_browser_token(std::string_view value) noexcept -> bool
    {
        if (value.size() != browser_token_chars)
        {
            return false;
        }
        for (auto const character : value)
        {
            if (!((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
            {
                return false;
            }
        }
        return true;
    }

    // The browser token the request's cookie carries, when it carries exactly one well-formed value.
    [[nodiscard]] auto request_browser_token(LocalHttpRequest const& request) -> std::optional<std::string>
    {
        auto const header = single_header(request, "Cookie");
        if (!header.has_value())
        {
            return std::nullopt;
        }
        auto parsed = core::RequestCookies::parse(*header);
        auto const* cookies = std::get_if<core::RequestCookies>(&parsed);
        if (cookies == nullptr)
        {
            return std::nullopt;
        }
        auto const value = cookies->find(oauth_browser_cookie_name);
        if (!value.has_value() || !is_browser_token(*value))
        {
            return std::nullopt;
        }
        return std::string{*value};
    }

    // The username a `login_hint` prefills (spec "Login flow" leaves its form to the server): `mxid:` and a valid user
    // ID of this server gives its localpart; a bare valid localpart gives itself; anything else nothing.
    [[nodiscard]] auto login_hint_username(std::optional<std::string_view> hint, std::string_view server_name)
        -> std::optional<std::string>
    {
        if (!hint.has_value() || hint->empty() || hint->size() > max_oauth_login_hint_bytes)
        {
            return std::nullopt;
        }
        constexpr auto mxid_prefix = std::string_view{"mxid:"};
        if (hint->starts_with(mxid_prefix))
        {
            auto const user_id = hint->substr(mxid_prefix.size());
            if (!auth::user_id_is_valid(user_id) || auth::user_id_server_name(user_id) != server_name)
            {
                return std::nullopt;
            }
            auto const localpart = user_id.substr(1U, user_id.find(':') - 1U);
            return auth::localpart_is_valid_new(localpart) ? std::optional<std::string>{std::string{localpart}}
                                                           : std::nullopt;
        }
        return auth::localpart_is_valid_new(*hint) ? std::optional<std::string>{std::string{*hint}} : std::nullopt;
    }

    // The registered client of a pending authorisation and its redirect URI matched again, for the consent page and
    // the final redirect. nullopt when the client is no longer registered (the address can no longer be validated).
    struct ClientTarget final
    {
        oauth::ClientMetadata metadata;
        oauth::ParsedUri redirect_target;
    };

    [[nodiscard]] auto client_target(HomeserverRuntime const& runtime, PendingAuthorisation const& entry)
        -> std::optional<ClientTarget>
    {
        auto metadata = find_registered_oauth_client(runtime, entry.client_id);
        if (!metadata.has_value())
        {
            return std::nullopt;
        }
        auto matched =
            oauth::match_redirect_uri(entry.redirect_uri, metadata->application_type(), metadata->redirect_uris());
        if (!matched.has_value())
        {
            return std::nullopt;
        }
        return ClientTarget{std::move(*metadata), std::move(*matched)};
    }

    // What every form post of one pending authorisation shares.
    struct FormPost final
    {
        ClientServerRuntime& runtime;
        LocalHttpRequest const& request;
        std::string pending_id;
        std::string browser_token;
        // The entry as found when the post arrived. Its fields never change, except `user_id`, which is read again
        // through the store after any call that released runtime.mutex.
        PendingAuthorisation entry;
    };

    [[nodiscard]] auto registration_enabled(HomeserverRuntime const& runtime) -> bool
    {
        return runtime.config.security().registration.enabled;
    }

    [[nodiscard]] auto login_form_input(HomeserverRuntime const& runtime, std::string_view pending_id)
        -> oauth::AccountFormInput
    {
        auto input = oauth::AccountFormInput{};
        input.server_name = runtime.config.server().server_name;
        input.pending_id = pending_id;
        input.offer_other_form = registration_enabled(runtime);
        return input;
    }

    [[nodiscard]] auto registration_form_input(HomeserverRuntime const& runtime, std::string_view pending_id)
        -> oauth::AccountFormInput
    {
        auto input = oauth::AccountFormInput{};
        input.server_name = runtime.config.server().server_name;
        input.pending_id = pending_id;
        input.offer_other_form = true;
        input.registration_token_required = runtime.config.security().registration.require_token;
        return input;
    }

    [[nodiscard]] auto registration_closed_notice() -> oauth::HtmlText
    {
        return oauth::HtmlText{"This server does not accept new accounts. Sign in with an existing account."};
    }

    [[nodiscard]] auto login_page_response(std::uint16_t status, oauth::AccountFormInput const& input)
        -> LocalHttpResponse
    {
        return plain_page(status, oauth::login_page(input));
    }

    [[nodiscard]] auto registration_page_response(std::uint16_t status, oauth::AccountFormInput const& input)
        -> LocalHttpResponse
    {
        return plain_page(status, oauth::registration_page(input));
    }

    // `Retry-After` in whole seconds, rounded up, at least one.
    [[nodiscard]] auto retry_after_seconds(std::uint32_t retry_after_ms) -> std::uint32_t
    {
        auto const seconds = (retry_after_ms / 1000U) + (retry_after_ms % 1000U == 0U ? 0U : 1U);
        return seconds == 0U ? 1U : seconds;
    }

    // The consent page for the pending authorisation `post` names, now authenticated as `user_id`. Its policy allows
    // the form post to be answered by a redirect to the matched redirect URI, and to nothing else (ADR-0772).
    [[nodiscard]] auto consent_response(FormPost const& post, std::string_view user_id) -> LocalHttpResponse
    {
        auto const& runtime = post.runtime.homeserver;
        auto const target = client_target(runtime, post.entry);
        if (!target.has_value())
        {
            return expired_page();
        }
        auto const& metadata = target->metadata;
        auto input = oauth::ConsentPageInput{};
        input.pending_id = post.pending_id;
        if (metadata.client_name().has_value())
        {
            input.client_name = *metadata.client_name();
        }
        input.client_host = metadata.client_uri().host_lower();
        input.user_id = user_id;
        input.device_id = post.entry.device_id;
        if (metadata.policy_uri().has_value())
        {
            input.policy_uri = *metadata.policy_uri();
        }
        if (metadata.tos_uri().has_value())
        {
            input.tos_uri = *metadata.tos_uri();
        }
        input.replaces_existing_device =
            database::has_user_device(runtime.database.persistent_store, user_id, post.entry.device_id);
        return page_response(status_ok, oauth::consent_page(input, target->redirect_target),
                             oauth::page_headers(target->redirect_target));
    }

    // Records `user_id` on the entry and answers the consent page. The store finds the entry again, so a login or a
    // registration that released runtime.mutex trusts nothing it read before: an entry that ended meanwhile is expired.
    [[nodiscard]] auto authenticated(FormPost const& post, std::string_view user_id) -> LocalHttpResponse
    {
        auto& store = post.runtime.homeserver.oauth_pending_authorisations;
        if (!store.record_user(post.pending_id, post.browser_token, user_id, oauth_wall_clock_ms()))
        {
            return expired_page();
        }
        return consent_response(post, user_id);
    }

    [[nodiscard]] auto handle_login(FormPost const& post, core::FormFields const& fields) -> LocalHttpResponse
    {
        auto& runtime = post.runtime.homeserver;
        auto input = login_form_input(runtime, post.pending_id);
        auto const username = fields.find(oauth::username_field.view());
        auto const password = fields.find(oauth::password_field.view());
        if (!username.has_value() || username->empty() || !password.has_value() || password->empty())
        {
            input.error = oauth::HtmlText{"Enter your username and password."};
            return login_page_response(status_bad_request, input);
        }
        input.username = *username;
        auto const invalid_login = [&input]() {
            input.error = oauth::HtmlText{"That username and password do not match an account on this server."};
            return login_page_response(status_unauthorized, input);
        };
        if (username->size() > max_login_username_bytes)
        {
            return invalid_login();
        }
        auto const user_id = login_identifier_user_id(runtime.config.server().server_name, *username);
        auto const client_key = rate_limit_client_key(post.request, runtime.config.server());
        // Releases runtime.mutex around Argon2id; the entry is read again by record_user below.
        auto const verified =
            verify_password_login(runtime, PasswordLoginRequest{user_id, *password, client_key, post.entry.device_id});
        switch (verified.outcome)
        {
        case Outcome::verified:
            return authenticated(post, verified.user_id);
        case Outcome::invalid_login:
            return invalid_login();
        case Outcome::account_deactivated:
            input.error = oauth::HtmlText{"This account has been deactivated and can no longer sign in."};
            return login_page_response(status_forbidden, input);
        case Outcome::throttled: {
            auto const seconds = retry_after_seconds(verified.retry_after_ms);
            auto const text = "Too many failed sign-in attempts for this account. Try again in " +
                              std::to_string(seconds) + " seconds.";
            auto message = oauth::HtmlText::escape(text);
            input.error = message.has_value() ? std::move(*message)
                                              : oauth::HtmlText{"Too many failed sign-in attempts. Try again later."};
            auto response = login_page_response(status_too_many_requests, input);
            response.headers.emplace_back("Retry-After", std::to_string(seconds));
            return response;
        }
        case Outcome::busy: {
            input.error = oauth::HtmlText{"The server is busy. Try again in a moment."};
            auto response = login_page_response(status_unavailable, input);
            response.headers.emplace_back("Retry-After", std::to_string(retry_after_seconds(verified.retry_after_ms)));
            return response;
        }
        }
        return invalid_login();
    }

    // The fixed message and status for a refused account creation, chosen from the result's status and errcode (and
    // its reason, compared, never shown).
    [[nodiscard]] auto registration_refusal(OperationResult const& result) -> std::pair<std::uint16_t, oauth::HtmlText>
    {
        if (result.errcode == "M_INVALID_USERNAME")
        {
            return {status_bad_request,
                    oauth::HtmlText{"This username cannot be used. Use lower-case letters, digits and the "
                                    "characters . _ = - / and +."}};
        }
        if (result.errcode == "M_USER_IN_USE" || result.reason == "user already exists")
        {
            return {status_bad_request, oauth::HtmlText{"This username is already taken. Choose another one."}};
        }
        if (result.errcode == "M_EXCLUSIVE")
        {
            return {status_bad_request, oauth::HtmlText{"This username is reserved. Choose another one."}};
        }
        if (result.errcode == "M_WEAK_PASSWORD")
        {
            return {status_bad_request,
                    oauth::HtmlText{"This password is too weak. Choose a longer one that is harder to guess."}};
        }
        if (result.reason == "registration token required" || result.reason == "registration token rejected")
        {
            return {status_forbidden, oauth::HtmlText{"The registration token is not valid."}};
        }
        if (result.status == status_too_many_requests)
        {
            return {status_unavailable, oauth::HtmlText{"The server is busy. Try again in a moment."}};
        }
        if (result.status == status_forbidden)
        {
            return {status_forbidden, oauth::HtmlText{"This server did not accept the new account."}};
        }
        return {status_server_error, oauth::HtmlText{"The account could not be created. Try again later."}};
    }

    [[nodiscard]] auto handle_register(FormPost const& post, core::FormFields const& fields) -> LocalHttpResponse
    {
        auto& runtime = post.runtime.homeserver;
        if (!registration_enabled(runtime))
        {
            auto input = login_form_input(runtime, post.pending_id);
            input.notice = registration_closed_notice();
            return login_page_response(status_forbidden, input);
        }
        auto input = registration_form_input(runtime, post.pending_id);
        auto const username = fields.find(oauth::username_field.view());
        auto const password = fields.find(oauth::password_field.view());
        auto const confirmation = fields.find(oauth::password_confirm_field.view());
        auto const token = input.registration_token_required ? fields.find(oauth::registration_token_field.view())
                                                             : std::optional<std::string_view>{std::string_view{}};
        // A username is shown again only when it could be an account's: never text that is not a valid localpart.
        if (username.has_value() && auth::localpart_is_valid_new(*username))
        {
            input.username = *username;
        }
        if (!username.has_value() || username->empty() || !password.has_value() || password->empty() ||
            !confirmation.has_value() || !token.has_value() || (input.registration_token_required && token->empty()))
        {
            input.error = oauth::HtmlText{"Fill in every field."};
            return registration_page_response(status_bad_request, input);
        }
        if (*password != *confirmation)
        {
            input.error = oauth::HtmlText{"The two passwords do not match."};
            return registration_page_response(status_bad_request, input);
        }
        auto const client_key = rate_limit_client_key(post.request, runtime.config.server());
        // Releases runtime.mutex around Argon2id; the entry is read again by record_user below.
        auto const created =
            create_local_account(runtime, AccountCreationRequest{*username, *password, *token, client_key});
        if (!created.ok)
        {
            auto [status, message] = registration_refusal(created);
            input.error = std::move(message);
            auto response = registration_page_response(status, input);
            if (status == status_unavailable)
            {
                response.headers.emplace_back("Retry-After",
                                              std::to_string(retry_after_seconds(created.retry_after_ms)));
            }
            return response;
        }
        return authenticated(post, created.value);
    }

    // `approve`: the entry must hold a verified user. It is spent, the account is judged again, and a code bound to the
    // whole request and the user is sent to the client.
    [[nodiscard]] auto handle_approve(FormPost const& post) -> LocalHttpResponse
    {
        auto& runtime = post.runtime.homeserver;
        if (post.entry.user_id.empty())
        {
            return expired_page();
        }
        auto const now_ms = oauth_wall_clock_ms();
        auto const consumed = runtime.oauth_pending_authorisations.consume(post.pending_id, post.browser_token, now_ms);
        if (!consumed.has_value() || consumed->user_id.empty())
        {
            return expired_page();
        }
        auto const target = client_target(runtime, *consumed);
        if (!target.has_value())
        {
            return expired_page();
        }
        auto const& redirect = target->redirect_target;
        if (account_sign_in_gate(runtime, consumed->user_id, consumed->device_id) != Outcome::verified)
        {
            log_refused(consumed->client_id, oauth::error_access_denied);
            return error_redirect(status_see_other, redirect, consumed->response_mode, oauth::error_access_denied,
                                  "The account cannot sign in.", consumed->state);
        }
        auto grant = AuthorizationGrant{};
        grant.client_id = consumed->client_id;
        grant.redirect_uri = consumed->redirect_uri;
        grant.code_challenge = consumed->code_challenge;
        grant.user_id = consumed->user_id;
        grant.device_id = consumed->device_id;
        grant.scope = consumed->scope;
        auto issued = runtime.oauth_codes.issue(std::move(grant), now_ms);
        auto const* code = std::get_if<std::string>(&issued);
        if (code == nullptr)
        {
            log_refused(consumed->client_id, oauth::error_temporarily_unavailable);
            return error_redirect(status_see_other, redirect, consumed->response_mode,
                                  oauth::error_temporarily_unavailable,
                                  "The server cannot complete the sign-in now. Try again later.", consumed->state);
        }
        log_oauth("oauth.authorization.granted",
                  {
                      {"client_id", consumed->client_id, false},
                      {"user_id",   consumed->user_id,   false},
                      {"device_id", consumed->device_id, false}
        },
                  observability::LogEventSeverity::info);
        append_local_audit(runtime.database, observability::AuditCategory::auth, "oauth.authorization.granted",
                           consumed->user_id, consumed->client_id, consumed->device_id);
        auto parameters = std::vector<oauth::RedirectParameter>{
            {"code", *code}
        };
        if (!consumed->state.empty())
        {
            parameters.emplace_back("state", consumed->state);
        }
        return redirect_response(status_see_other, redirect, consumed->response_mode, parameters);
    }

    [[nodiscard]] auto handle_deny(FormPost const& post) -> LocalHttpResponse
    {
        auto& runtime = post.runtime.homeserver;
        auto const consumed =
            runtime.oauth_pending_authorisations.consume(post.pending_id, post.browser_token, oauth_wall_clock_ms());
        if (!consumed.has_value())
        {
            return expired_page();
        }
        auto const target = client_target(runtime, *consumed);
        if (!target.has_value())
        {
            return expired_page();
        }
        log_oauth("oauth.authorization.denied",
                  {
                      {"client_id", consumed->client_id, false},
                      {"user_id",   consumed->user_id,   false},
                      {"device_id", consumed->device_id, false}
        },
                  observability::LogEventSeverity::info);
        // Audited only for a signed-in user: a denial before the password is anyone's to send.
        if (!consumed->user_id.empty())
        {
            append_local_audit(runtime.database, observability::AuditCategory::auth, "oauth.authorization.denied",
                               consumed->user_id, consumed->client_id, consumed->device_id);
        }
        return error_redirect(status_see_other, target->redirect_target, consumed->response_mode,
                              oauth::error_access_denied, "The user denied the request.", consumed->state);
    }

    // `application/x-www-form-urlencoded`, in any ASCII case, with no parameter: what an HTML form posts.
    [[nodiscard]] auto is_form_content_type(std::string_view content_type) noexcept -> bool
    {
        constexpr auto expected = std::string_view{"application/x-www-form-urlencoded"};
        if (content_type.size() != expected.size())
        {
            return false;
        }
        for (auto index = std::size_t{0U}; index < expected.size(); ++index)
        {
            auto value = content_type[index];
            if (value >= 'A' && value <= 'Z')
            {
                value = static_cast<char>(value - 'A' + 'a');
            }
            if (value != expected[index])
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto handle_post(ClientServerRuntime& rt, LocalHttpRequest const& request) -> LocalHttpResponse
    {
        auto& runtime = rt.homeserver;
        auto base = oauth::OAuthBaseUrl::read(runtime.config.server().public_baseurl);
        auto const* base_url = std::get_if<oauth::OAuthBaseUrl>(&base);
        if (base_url == nullptr)
        {
            return error_page_response(
                status_server_error, oauth::HtmlText{"Sign-in is not available"},
                oauth::HtmlText{"This server is not configured for sign-in through applications."});
        }
        // Before anything is read: another site's post is refused whatever it carries (ADR-0784, ADR-0788).
        if (!oauth::form_post_origin_is_accepted(*base_url, single_header(request, "Origin"),
                                                 single_header(request, "Sec-Fetch-Site")))
        {
            log_refused({}, "forbidden_origin");
            return error_page_response(status_forbidden, oauth::HtmlText{"Form refused"},
                                       oauth::HtmlText{"This form was not sent from a page of this server."});
        }
        auto const content_type = single_header(request, "Content-Type");
        if (!content_type.has_value() || !is_form_content_type(*content_type))
        {
            return error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                       oauth::HtmlText{"This form could not be read."});
        }
        auto parsed = core::FormFields::parse(request.body);
        auto const* fields = std::get_if<core::FormFields>(&parsed);
        if (fields == nullptr)
        {
            return error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                       oauth::HtmlText{"This form could not be read."});
        }
        auto const pending_id = fields->find(oauth::pending_field.view());
        auto browser_token = request_browser_token(request);
        if (!pending_id.has_value() || pending_id->empty() || !browser_token.has_value())
        {
            return expired_page();
        }
        auto entry = runtime.oauth_pending_authorisations.find(*pending_id, *browser_token, oauth_wall_clock_ms());
        if (!entry.has_value())
        {
            return expired_page();
        }
        auto const post = FormPost{rt, request, std::string{*pending_id}, std::move(*browser_token), std::move(*entry)};
        auto const action = fields->find(oauth::action_field.view()).value_or(std::string_view{});
        if (action == oauth::action_login.view())
        {
            return handle_login(post, *fields);
        }
        if (action == oauth::action_register.view())
        {
            return handle_register(post, *fields);
        }
        if (action == oauth::action_show_register.view())
        {
            if (!registration_enabled(runtime))
            {
                auto input = login_form_input(runtime, post.pending_id);
                input.notice = registration_closed_notice();
                return login_page_response(status_ok, input);
            }
            return registration_page_response(status_ok, registration_form_input(runtime, post.pending_id));
        }
        if (action == oauth::action_show_login.view())
        {
            return login_page_response(status_ok, login_form_input(runtime, post.pending_id));
        }
        if (action == oauth::action_approve.view())
        {
            return handle_approve(post);
        }
        if (action == oauth::action_deny.view())
        {
            return handle_deny(post);
        }
        return error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                   oauth::HtmlText{"This form asked for something this page does not do."});
    }

    // What the `prompt` parameter asks the first page to be.
    enum class FirstPage : std::uint8_t
    {
        login,
        registration,
        registration_closed,
    };

    [[nodiscard]] auto handle_get(ClientServerRuntime& rt, LocalHttpRequest const& request) -> LocalHttpResponse
    {
        auto& runtime = rt.homeserver;
        // Step 1: the client and its redirect URI. Nothing here is ever sent to an address.
        auto parsed = core::FormFields::parse(target_query(request.target));
        auto const* fields = std::get_if<core::FormFields>(&parsed);
        if (fields == nullptr)
        {
            log_refused({}, oauth::error_invalid_request);
            return bad_request_page(
                oauth::HtmlText{"The request is malformed. Return to the application and try again."});
        }
        auto const client_id = fields->find("client_id");
        auto const metadata = client_id.has_value() ? find_registered_oauth_client(runtime, *client_id)
                                                    : std::optional<oauth::ClientMetadata>{};
        if (!metadata.has_value())
        {
            log_refused({}, oauth::error_invalid_request);
            return bad_request_page(oauth::HtmlText{"The application that sent you here is not registered with this "
                                                    "server. Return to the application and try again."});
        }
        auto const requested_redirect = fields->find("redirect_uri");
        auto const matched = requested_redirect.has_value()
                                 ? oauth::match_redirect_uri(*requested_redirect, metadata->application_type(),
                                                             metadata->redirect_uris())
                                 : std::optional<oauth::ParsedUri>{};
        if (!matched.has_value())
        {
            log_refused(*client_id, oauth::error_invalid_request);
            return bad_request_page(oauth::HtmlText{"The application asked to return to an address it did not "
                                                    "register. Return to the application and try again."});
        }

        // Step 2: every refusal from here is redirected to the matched address.
        auto const response_mode = fields->find("response_mode");
        auto const mode = response_mode == std::optional<std::string_view>{"fragment"} ? oauth::ResponseMode::fragment
                                                                                       : oauth::ResponseMode::query;
        auto const refuse = [&](std::string_view error_code, std::string_view description,
                                std::string_view returned_state) -> LocalHttpResponse {
            log_refused(*client_id, error_code);
            return error_redirect(status_found, *matched, mode, error_code, description, returned_state);
        };
        auto const state = fields->find("state").value_or(std::string_view{});
        if (state.size() > max_oauth_state_bytes)
        {
            return refuse(oauth::error_invalid_request, "The state parameter is too long.", {});
        }
        auto const response_type = fields->find("response_type");
        if (!response_type.has_value())
        {
            return refuse(oauth::error_invalid_request, "The response_type parameter is missing.", state);
        }
        if (*response_type != oauth::response_type_code)
        {
            return refuse(oauth::error_unsupported_response_type, "Only the response type code is supported.", state);
        }
        if (!metadata->has_grant_type(oauth::grant_type_authorization_code))
        {
            return refuse(oauth::error_unauthorized_client,
                          "The client is not registered for the authorization code grant.", state);
        }
        if (response_mode.has_value() && *response_mode != "query" && *response_mode != "fragment")
        {
            return refuse(oauth::error_invalid_request, "The response_mode must be query or fragment.", state);
        }
        if (fields->find("code_challenge_method") != std::optional<std::string_view>{oauth::pkce_method_s256})
        {
            return refuse(oauth::error_invalid_request, "PKCE with the code challenge method S256 is required.", state);
        }
        auto const challenge = fields->find("code_challenge");
        if (!challenge.has_value() || !oauth::pkce_challenge_is_valid(*challenge))
        {
            return refuse(oauth::error_invalid_request, "The code_challenge is missing or is not an S256 challenge.",
                          state);
        }
        auto scope = oauth::parse_scope(fields->find("scope").value_or(std::string_view{}));
        if (auto const* refused = std::get_if<oauth::OAuthRefusal>(&scope); refused != nullptr)
        {
            return refuse(refused->error_code, refused->error.message(), state);
        }
        auto const& granted = std::get<oauth::GrantedScope>(scope);
        auto first_page = FirstPage::login;
        if (auto const prompt = fields->find("prompt"); prompt.has_value())
        {
            if (*prompt == "none")
            {
                return refuse(oauth::error_login_required, "This server always asks the user to sign in.", state);
            }
            if (*prompt == "create")
            {
                first_page = registration_enabled(runtime) ? FirstPage::registration : FirstPage::registration_closed;
            }
            else if (*prompt != "consent" && *prompt != "login" && *prompt != "select_account")
            {
                return refuse(oauth::error_invalid_request, "The prompt value is not supported.", state);
            }
        }
        auto const& server_name = runtime.config.server().server_name;
        auto const hint = login_hint_username(fields->find("login_hint"), server_name);

        // Step 3: bind a pending authorisation to this browser.
        auto browser_token = request_browser_token(request);
        if (!browser_token.has_value())
        {
            browser_token = make_oauth_secret();
        }
        auto const cookie = browser_token.has_value()
                                ? core::host_cookie(oauth_browser_cookie_name, *browser_token,
                                                    core::CookieSameSite::lax, oauth_browser_cookie_max_age_seconds)
                                : std::variant<std::string, core::Error>{core::Error{}};
        auto const* set_cookie = std::get_if<std::string>(&cookie);
        if (set_cookie == nullptr)
        {
            return error_page_response(status_unavailable, oauth::HtmlText{"Sign-in is not available"},
                                       oauth::HtmlText{"The server cannot start a sign-in now. Try again later."});
        }
        auto authorisation = PendingAuthorisation{};
        authorisation.client_id = std::string{*client_id};
        authorisation.redirect_uri = std::string{*requested_redirect};
        authorisation.response_mode = mode;
        authorisation.state = std::string{state};
        authorisation.code_challenge = std::string{*challenge};
        authorisation.device_id = granted.device_id;
        authorisation.scope = granted.scope;
        authorisation.create_account = first_page != FirstPage::login;
        if (hint.has_value())
        {
            authorisation.login_hint = *hint;
        }
        auto created = runtime.oauth_pending_authorisations.create(
            std::move(authorisation), *browser_token, rate_limit_client_key(request, runtime.config.server()),
            oauth_wall_clock_ms());
        auto const* pending_id = std::get_if<std::string>(&created);
        if (pending_id == nullptr)
        {
            log_refused(*client_id, oauth::error_temporarily_unavailable);
            return error_page_response(
                status_unavailable, oauth::HtmlText{"Sign-in is not available"},
                oauth::HtmlText{"Too many sign-ins are in progress. Try again in a few minutes."});
        }
        log_oauth("oauth.authorization.started",
                  {
                      {"client_id",        std::string{*client_id},                                          false},
                      {"application_type", std::string{application_type_name(metadata->application_type())}, false}
        },
                  observability::LogEventSeverity::debug);

        auto response = std::invoke([&]() {
            if (first_page == FirstPage::registration)
            {
                return registration_page_response(status_ok, registration_form_input(runtime, *pending_id));
            }
            auto input = login_form_input(runtime, *pending_id);
            if (hint.has_value())
            {
                input.username = *hint;
            }
            if (first_page == FirstPage::registration_closed)
            {
                input.notice = registration_closed_notice();
            }
            return login_page_response(status_ok, input);
        });
        response.headers.emplace_back("Set-Cookie", *set_cookie);
        return response;
    }

} // namespace

auto handle_oauth_authorize(ClientServerRuntime& runtime, LocalHttpRequest const& request) -> LocalHttpResponse
{
    if (request.method == "POST")
    {
        return handle_post(runtime, request);
    }
    return handle_get(runtime, request);
}

} // namespace merovingian::homeserver
