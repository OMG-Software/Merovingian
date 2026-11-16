// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthAuthorization.hpp"

#include "merovingian/auth/Identity.hpp"
#include "merovingian/core/CookieSameSite.hpp"
#include "merovingian/core/Error.hpp"
#include "merovingian/core/FormFields.hpp"
#include "merovingian/core/HostCookie.hpp"
#include "merovingian/crypto/Random.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AccountCreationRequest.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/AuthorizationCodeStore.hpp"
#include "merovingian/homeserver/AuthorizationGrant.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/DeviceAuthorisationStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/LocalServices.hpp"
#include "merovingian/homeserver/LoginTokenStore.hpp"
#include "merovingian/homeserver/OAuthClientRegistration.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"
#include "merovingian/homeserver/OAuthPageResponse.hpp"
#include "merovingian/homeserver/OAuthSecret.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/PasswordLoginRequest.hpp"
#include "merovingian/homeserver/PasswordLoginVerification.hpp"
#include "merovingian/homeserver/PendingAuthorisation.hpp"
#include "merovingian/homeserver/PendingAuthorisationKind.hpp"
#include "merovingian/homeserver/PendingAuthorisationStore.hpp"
#include "merovingian/oauth/AccountFormInput.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/AuthorizationPages.hpp"
#include "merovingian/oauth/AuthorizationRedirect.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"
#include "merovingian/oauth/ConsentPageInput.hpp"
#include "merovingian/oauth/DeviceConsentPageInput.hpp"
#include "merovingian/oauth/FormContentType.hpp"
#include "merovingian/oauth/FormPostOrigin.hpp"
#include "merovingian/oauth/GrantedScope.hpp"
#include "merovingian/oauth/HandOffRedirect.hpp"
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
#include "merovingian/oauth/UserCode.hpp"
#include "merovingian/observability/AuditCategory.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
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
    constexpr auto status_conflict = std::uint16_t{409U};
    constexpr auto status_too_many_requests = std::uint16_t{429U};
    constexpr auto status_server_error = std::uint16_t{500U};
    constexpr auto status_unavailable = std::uint16_t{503U};
    // A hand-off's login token: 32 random bytes, as get_token mints, and redeemable for 30 seconds (ADR-0802).
    constexpr auto login_token_bytes = std::size_t{32U};
    // The longest username read from the login form: a user ID is at most 255 bytes, so no account has a longer one.
    constexpr auto max_login_username_bytes = std::size_t{255U};

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

    // Step 1 of the request: nothing is redirected, because no address has been validated.
    [[nodiscard]] auto bad_request_page(oauth::HtmlText const& message) -> LocalHttpResponse
    {
        return oauth_error_page_response(status_bad_request, oauth::HtmlText{"This sign-in request cannot be used"},
                                         message);
    }

    // The answer to a form post whose pending authorisation is gone, never was, or is bound to another browser. The
    // server no longer holds a validated address for it, so the user is sent back to the application by hand.
    [[nodiscard]] auto expired_page() -> LocalHttpResponse
    {
        return oauth_error_page_response(
            status_bad_request, oauth::HtmlText{"Sign-in expired"},
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

    [[nodiscard]] auto is_hand_off(PendingAuthorisation const& entry) noexcept -> bool
    {
        return entry.kind == PendingAuthorisationKind::login_token_hand_off;
    }

    // A hand-off's `redirectUrl` read again under the rules and the allowlist in force now, for the confirmation page
    // and the final redirect. nullopt when it no longer passes.
    [[nodiscard]] auto hand_off_target(HomeserverRuntime const& runtime, PendingAuthorisation const& entry)
        -> std::optional<oauth::ParsedUri>
    {
        return oauth::hand_off_redirect_target(entry.redirect_uri,
                                               runtime.config.server().oauth.hand_off_redirect_allowlist);
    }

    auto log_hand_off(std::string_view event, std::string_view user_id, observability::LogEventSeverity severity)
        -> void
    {
        auto fields = std::vector<observability::StructuredLogField>{};
        if (!user_id.empty())
        {
            fields.push_back({"user_id", std::string{user_id}, false});
        }
        log_oauth(event, std::move(fields), severity);
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

    [[nodiscard]] auto is_device_sign_in(PendingAuthorisation const& entry) noexcept -> bool
    {
        return entry.kind == PendingAuthorisationKind::device_authorization;
    }

    // The login page offers registration only when it is enabled, and never for a device sign-in, which signs a
    // device in to an account that exists (ADR-0806).
    [[nodiscard]] auto login_form_input(HomeserverRuntime const& runtime, std::string_view pending_id,
                                        PendingAuthorisationKind kind) -> oauth::AccountFormInput
    {
        auto input = oauth::AccountFormInput{};
        input.server_name = runtime.config.server().server_name;
        input.pending_id = pending_id;
        input.offer_other_form =
            registration_enabled(runtime) && kind != PendingAuthorisationKind::device_authorization;
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
        return oauth_plain_page(status, oauth::login_page(input));
    }

    [[nodiscard]] auto registration_page_response(std::uint16_t status, oauth::AccountFormInput const& input)
        -> LocalHttpResponse
    {
        return oauth_plain_page(status, oauth::registration_page(input));
    }

    // The answer when a device sign-in's entry ended, was answered, or was taken over by another browser (ADR-0806).
    [[nodiscard]] auto device_sign_in_ended_page() -> LocalHttpResponse
    {
        return oauth_error_page_response(
            status_bad_request, oauth::HtmlText{"Device sign-in ended"},
            oauth::HtmlText{"This device sign-in has expired, was already answered, or was continued in another "
                            "browser. Enter the code your device shows again."});
    }

    // Logs a device sign-in's answer: the client, the user and the device. Never the user code, the device code or
    // the cookie.
    auto log_device_answer(std::string_view event, PendingAuthorisation const& entry) -> void
    {
        log_oauth(event,
                  {
                      {"client_id", entry.client_id, false},
                      {"user_id",   entry.user_id,   false},
                      {"device_id", entry.device_id, false}
        },
                  observability::LogEventSeverity::info);
    }

    // The consent page of a device sign-in (ADR-0806): the code, read again from the device authorisation this browser
    // still holds, and the client, read again from its registration. No redirect follows, so the page carries the
    // plain headers.
    [[nodiscard]] auto device_consent_response(FormPost const& post, std::string_view user_id) -> LocalHttpResponse
    {
        auto& runtime = post.runtime.homeserver;
        auto const device = runtime.oauth_device_authorisations.find_attached(
            post.entry.device_authorisation_key, post.entry.device_attachment, oauth_device_clock_ms(runtime));
        auto const metadata = find_registered_oauth_client(runtime, post.entry.client_id);
        if (!device.has_value() || !metadata.has_value())
        {
            return device_sign_in_ended_page();
        }
        auto input = oauth::DeviceConsentPageInput{};
        input.pending_id = post.pending_id;
        input.user_code = device->user_code;
        if (metadata->client_name().has_value())
        {
            input.client_name = *metadata->client_name();
        }
        input.client_host = metadata->client_uri().host_lower();
        input.user_id = user_id;
        input.device_id = post.entry.device_id;
        input.replaces_existing_device =
            database::has_user_device(runtime.database.persistent_store, user_id, post.entry.device_id);
        return oauth_plain_page(status_ok, oauth::device_consent_page(input));
    }

    // The consent page for the pending authorisation `post` names, now authenticated as `user_id`. Its policy allows
    // the form post to be answered by a redirect to the matched redirect URI, and to nothing else (ADR-0772).
    [[nodiscard]] auto consent_response(FormPost const& post, std::string_view user_id) -> LocalHttpResponse
    {
        if (is_device_sign_in(post.entry))
        {
            return device_consent_response(post, user_id);
        }
        auto const& runtime = post.runtime.homeserver;
        if (is_hand_off(post.entry))
        {
            // The confirmation page (ADR-0802): it names the account and where the browser goes, and its policy allows
            // the redirect to that address alone.
            auto const destination = hand_off_target(runtime, post.entry);
            if (!destination.has_value())
            {
                return expired_page();
            }
            return oauth_page_response(status_ok, oauth::hand_off_page(post.pending_id, user_id, *destination),
                                       oauth::page_headers(*destination));
        }
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
        return oauth_page_response(status_ok, oauth::consent_page(input, target->redirect_target),
                                   oauth::page_headers(target->redirect_target));
    }

    // Records `user_id` on the entry and answers the consent page. The store finds the entry again, so a login or a
    // registration that released runtime.mutex trusts nothing it read before: an entry that ended meanwhile is expired.
    [[nodiscard]] auto authenticated(FormPost const& post, std::string_view user_id) -> LocalHttpResponse
    {
        auto& store = post.runtime.homeserver.oauth_pending_authorisations;
        // Taken under the same hold of runtime.mutex that verified the password (or created the account), so it is the
        // stamp of the credential just checked (ADR-0807).
        auto const stamp = user_credential_stamp(post.runtime.homeserver, user_id);
        if (!stamp.has_value() ||
            !store.record_user(post.pending_id, post.browser_token, user_id, *stamp, oauth_wall_clock_ms()))
        {
            return expired_page();
        }
        // A device sign-in keeps its hold on the device authorisation while its user is active (ADR-0806); one taken
        // over meanwhile by another browser ends here.
        auto& devices = post.runtime.homeserver.oauth_device_authorisations;
        if (is_device_sign_in(post.entry) &&
            !devices.renew(post.entry.device_authorisation_key, post.entry.device_attachment,
                           oauth_device_clock_ms(post.runtime.homeserver)))
        {
            return device_sign_in_ended_page();
        }
        return consent_response(post, user_id);
    }

    [[nodiscard]] auto handle_login(FormPost const& post, core::FormFields const& fields) -> LocalHttpResponse
    {
        auto& runtime = post.runtime.homeserver;
        auto input = login_form_input(runtime, post.pending_id, post.entry.kind);
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
            auto input = login_form_input(runtime, post.pending_id, post.entry.kind);
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

    // `approve` of a hand-off, its entry already spent: the account is judged again, and a single-use login token for
    // the user is minted into the store get_token uses and added to the `redirectUrl` (ADR-0802). Refusals are pages:
    // the address is the application's, and an error there would mean nothing to it.
    [[nodiscard]] auto finish_hand_off(ClientServerRuntime& rt, PendingAuthorisation const& consumed)
        -> LocalHttpResponse
    {
        auto& runtime = rt.homeserver;
        auto const target = hand_off_target(runtime, consumed);
        if (!target.has_value())
        {
            return expired_page();
        }
        if (account_sign_in_gate(runtime, consumed.user_id, {}) != Outcome::verified)
        {
            log_hand_off("oauth.hand_off.refused", consumed.user_id, observability::LogEventSeverity::info);
            return oauth_error_page_response(status_forbidden, oauth::HtmlText{"Sign-in refused"},
                                             oauth::HtmlText{"This account cannot sign in."});
        }
        auto const unavailable = []() {
            return oauth_error_page_response(
                status_unavailable, oauth::HtmlText{"Sign-in is not available"},
                oauth::HtmlText{"The server cannot complete the sign-in now. Try again later."});
        };
        auto const token = crypto::secure_random_hex(login_token_bytes);
        auto token_hash = token.has_value() ? LoginTokenStore::token_hash(*token) : std::nullopt;
        if (!token_hash.has_value())
        {
            return unavailable();
        }
        auto const issued = rt.login_tokens.issue(consumed.user_id, std::move(*token_hash), oauth_wall_clock_ms(),
                                                  hand_off_login_token_lifetime_ms, rt.limits.max_login_tokens_per_user,
                                                  rt.limits.max_login_tokens);
        if (issued.outcome != LoginTokenStore::IssueOutcome::issued)
        {
            log_hand_off("oauth.hand_off.refused", consumed.user_id, observability::LogEventSeverity::info);
            return unavailable();
        }
        auto const address = oauth::hand_off_return_address(*target, *token);
        if (!address.has_value())
        {
            return unavailable();
        }
        log_hand_off("oauth.hand_off.granted", consumed.user_id, observability::LogEventSeverity::info);
        append_local_audit(runtime.database, observability::AuditCategory::auth, "auth.login_token.issued",
                           consumed.user_id, {}, "hand_off");
        auto response = LocalHttpResponse{};
        response.status = status_see_other;
        response.headers = {
            {"Location",        *address     },
            {"Cache-Control",   "no-store"   },
            {"Referrer-Policy", "no-referrer"},
        };
        response.page = true;
        return response;
    }

    // `approve` or `deny` of a device sign-in, its pending entry already spent (ADR-0806): the device authorisation is
    // answered if this browser still holds it, and the browser stays here either way. An approval first judges the
    // account again; a refused account leaves the device authorisation pending and lets another browser take it.
    [[nodiscard]] auto finish_device_sign_in(ClientServerRuntime& rt, PendingAuthorisation const& consumed,
                                             bool approve) -> LocalHttpResponse
    {
        auto& runtime = rt.homeserver;
        auto& devices = runtime.oauth_device_authorisations;
        if (consumed.user_id.empty())
        {
            devices.release(consumed.device_authorisation_key, consumed.device_attachment);
            return device_sign_in_ended_page();
        }
        if (approve && account_sign_in_gate(runtime, consumed.user_id, consumed.device_id) != Outcome::verified)
        {
            devices.release(consumed.device_authorisation_key, consumed.device_attachment);
            log_refused(consumed.client_id, oauth::error_access_denied);
            return oauth_error_page_response(status_forbidden, oauth::HtmlText{"Sign-in refused"},
                                             oauth::HtmlText{"This account cannot sign in."});
        }
        if (!devices.decide(consumed.device_authorisation_key, consumed.device_attachment, consumed.user_id,
                            consumed.credential_stamp, approve, oauth_device_clock_ms(runtime)))
        {
            return device_sign_in_ended_page();
        }
        auto const event =
            approve ? std::string_view{"oauth.device.approved"} : std::string_view{"oauth.device.denied"};
        log_device_answer(event, consumed);
        append_local_audit(runtime.database, observability::AuditCategory::auth, event, consumed.user_id,
                           consumed.client_id, consumed.device_id);
        return oauth_plain_page(status_ok, approve ? oauth::device_approved_page() : oauth::device_denied_page());
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
        // The password that signed in must still be the account's (ADR-0807): a change, reset or deactivation since
        // ends this sign-in of every kind, and the entry is already spent.
        if (!user_credential_stamp_matches(runtime, consumed->user_id, consumed->credential_stamp))
        {
            if (is_device_sign_in(*consumed))
            {
                runtime.oauth_device_authorisations.release(consumed->device_authorisation_key,
                                                            consumed->device_attachment);
            }
            log_oauth("oauth.authorization.credentials_changed",
                      {
                          {"client_id", consumed->client_id, false},
                          {"user_id",   consumed->user_id,   false}
            },
                      observability::LogEventSeverity::info);
            return expired_page();
        }
        if (is_hand_off(*consumed))
        {
            return finish_hand_off(post.runtime, *consumed);
        }
        if (is_device_sign_in(*consumed))
        {
            return finish_device_sign_in(post.runtime, *consumed, true);
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
        grant.credential_stamp = consumed->credential_stamp;
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
        if (is_hand_off(*consumed))
        {
            // Nothing is sent to the application: the browser stays on this server (ADR-0802).
            log_hand_off("oauth.hand_off.cancelled", consumed->user_id, observability::LogEventSeverity::info);
            return oauth_plain_page(status_ok, oauth::hand_off_cancelled_page());
        }
        if (is_device_sign_in(*consumed))
        {
            return finish_device_sign_in(post.runtime, *consumed, false);
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

    [[nodiscard]] auto handle_post(ClientServerRuntime& rt, LocalHttpRequest const& request) -> LocalHttpResponse
    {
        auto& runtime = rt.homeserver;
        auto base = oauth::OAuthBaseUrl::read(runtime.config.server().public_baseurl);
        auto const* base_url = std::get_if<oauth::OAuthBaseUrl>(&base);
        if (base_url == nullptr)
        {
            return oauth_error_page_response(
                status_server_error, oauth::HtmlText{"Sign-in is not available"},
                oauth::HtmlText{"This server is not configured for sign-in through applications."});
        }
        // Before anything is read: another site's post is refused whatever it carries (ADR-0784, ADR-0788).
        if (!oauth::form_post_origin_is_accepted(*base_url, single_request_header(request, "Origin"),
                                                 single_request_header(request, "Sec-Fetch-Site")))
        {
            log_refused({}, "forbidden_origin");
            return oauth_error_page_response(status_forbidden, oauth::HtmlText{"Form refused"},
                                             oauth::HtmlText{"This form was not sent from a page of this server."});
        }
        auto const content_type = single_request_header(request, "Content-Type");
        if (!content_type.has_value() || !oauth::page_form_content_type_is_accepted(*content_type))
        {
            return oauth_error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                             oauth::HtmlText{"This form could not be read."});
        }
        auto parsed = core::FormFields::parse(request.body);
        auto const* fields = std::get_if<core::FormFields>(&parsed);
        if (fields == nullptr)
        {
            return oauth_error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                             oauth::HtmlText{"This form could not be read."});
        }
        auto const pending_id = fields->find(oauth::pending_field.view());
        auto browser_token = request_secret_cookie(request, oauth_browser_cookie_name);
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
        // A device sign-in signs a device in to an account that exists; it never creates one (ADR-0806).
        if (is_device_sign_in(post.entry) &&
            (action == oauth::action_register.view() || action == oauth::action_show_register.view()))
        {
            return oauth_error_page_response(status_forbidden, oauth::HtmlText{"Form refused"},
                                             oauth::HtmlText{"A device can only be signed in to an existing account."});
        }
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
                auto input = login_form_input(runtime, post.pending_id, post.entry.kind);
                input.notice = registration_closed_notice();
                return login_page_response(status_ok, input);
            }
            return registration_page_response(status_ok, registration_form_input(runtime, post.pending_id));
        }
        if (action == oauth::action_show_login.view())
        {
            return login_page_response(status_ok, login_form_input(runtime, post.pending_id, post.entry.kind));
        }
        if (action == oauth::action_approve.view())
        {
            return handle_approve(post);
        }
        if (action == oauth::action_deny.view())
        {
            return handle_deny(post);
        }
        return oauth_error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                         oauth::HtmlText{"This form asked for something this page does not do."});
    }

    // What the `prompt` parameter (or the hand-off's `action`) asks the first page to be.
    enum class FirstPage : std::uint8_t
    {
        login,
        registration,
        registration_closed,
    };

    // The first page of a sign-in and whether the sign-in started: false when no cookie could be made or the store
    // refused the entry, and the page says so.
    struct SignInStart final
    {
        LocalHttpResponse response;
        bool started{false};
    };

    // Binds `authorisation` to this browser's cookie (reused when the request carries a well-formed one, else fresh),
    // stores it and answers the first page with the cookie. Shared by the authorisation request and the hand-off.
    [[nodiscard]] auto start_sign_in(ClientServerRuntime& rt, LocalHttpRequest const& request,
                                     PendingAuthorisation authorisation, FirstPage first_page) -> SignInStart
    {
        auto& runtime = rt.homeserver;
        auto browser_token = request_secret_cookie(request, oauth_browser_cookie_name);
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
            return SignInStart{
                oauth_error_page_response(status_unavailable, oauth::HtmlText{"Sign-in is not available"},
                                          oauth::HtmlText{"The server cannot start a sign-in now. Try again later."}),
                false};
        }
        auto const hint = authorisation.login_hint;
        auto const kind = authorisation.kind;
        auto created = runtime.oauth_pending_authorisations.create(
            std::move(authorisation), *browser_token, rate_limit_client_key(request, runtime.config.server()),
            oauth_wall_clock_ms());
        auto const* pending_id = std::get_if<std::string>(&created);
        if (pending_id == nullptr)
        {
            return SignInStart{oauth_error_page_response(
                                   status_unavailable, oauth::HtmlText{"Sign-in is not available"},
                                   oauth::HtmlText{"Too many sign-ins are in progress. Try again in a few minutes."}),
                               false};
        }
        auto response = std::invoke([&]() {
            if (first_page == FirstPage::registration)
            {
                return registration_page_response(status_ok, registration_form_input(runtime, *pending_id));
            }
            auto input = login_form_input(runtime, *pending_id, kind);
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
        return SignInStart{std::move(response), true};
    }

    [[nodiscard]] auto handle_get(ClientServerRuntime& rt, LocalHttpRequest const& request) -> LocalHttpResponse
    {
        auto& runtime = rt.homeserver;
        // Step 1: the client and its redirect URI. Nothing here is ever sent to an address.
        auto parsed = core::FormFields::parse_query(request_target_query(request.target));
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
        auto start = start_sign_in(rt, request, std::move(authorisation), first_page);
        if (!start.started)
        {
            log_refused(*client_id, oauth::error_temporarily_unavailable);
            return std::move(start.response);
        }
        log_oauth("oauth.authorization.started",
                  {
                      {"client_id",        std::string{*client_id},                                          false},
                      {"application_type", std::string{application_type_name(metadata->application_type())}, false}
        },
                  observability::LogEventSeverity::debug);
        return std::move(start.response);
    }

    // The link page with `status`, a fixed `error` when there is one, and the code to prefill.
    [[nodiscard]] auto link_page_response(std::uint16_t status, std::optional<std::string_view> user_code,
                                          std::optional<oauth::HtmlText> const& error) -> LocalHttpResponse
    {
        return oauth_plain_page(status, oauth::device_link_page(user_code, error));
    }

    // This browser's cookie value, reused when the request carries a well-formed one, else fresh, and the
    // `Set-Cookie` header that (re)sets it; nullopt when neither a value nor the header could be made.
    struct BrowserCookie final
    {
        std::string token;
        std::string set_cookie;
    };

    [[nodiscard]] auto browser_cookie(LocalHttpRequest const& request) -> std::optional<BrowserCookie>
    {
        auto token = request_secret_cookie(request, oauth_browser_cookie_name);
        if (!token.has_value())
        {
            token = make_oauth_secret();
        }
        if (!token.has_value())
        {
            return std::nullopt;
        }
        auto cookie = core::host_cookie(oauth_browser_cookie_name, *token, core::CookieSameSite::lax,
                                        oauth_browser_cookie_max_age_seconds);
        auto* const header = std::get_if<std::string>(&cookie);
        if (header == nullptr)
        {
            return std::nullopt;
        }
        return BrowserCookie{std::move(*token), std::move(*header)};
    }

    [[nodiscard]] auto link_unavailable_page() -> LocalHttpResponse
    {
        return oauth_error_page_response(status_unavailable, oauth::HtmlText{"Sign-in is not available"},
                                         oauth::HtmlText{"The server cannot start a sign-in now. Try again later."});
    }

    // `GET /_merovingian/oauth2/link`: the form, prefilled from `user_code` only when it reads as a code, with the
    // browser cookie the form post needs. Nothing is looked up: the user confirms the code by sending the form.
    [[nodiscard]] auto handle_link_get(LocalHttpRequest const& request) -> LocalHttpResponse
    {
        auto parsed = core::FormFields::parse_query(request_target_query(request.target));
        auto const* fields = std::get_if<core::FormFields>(&parsed);
        auto prefill = std::optional<std::string>{};
        if (fields != nullptr)
        {
            if (auto const typed = fields->find("user_code"); typed.has_value())
            {
                prefill = oauth::normalise_user_code(*typed);
            }
        }
        auto const cookie = browser_cookie(request);
        if (!cookie.has_value())
        {
            return link_unavailable_page();
        }
        auto response = link_page_response(status_ok, prefill, std::nullopt);
        response.headers.emplace_back("Set-Cookie", cookie->set_cookie);
        return response;
    }

    // A wrong or expired code, counted against the address. The block is logged once, when it is reached.
    [[nodiscard]] auto wrong_code(ClientServerRuntime& rt, std::string_view client_key, std::uint64_t now_ms)
        -> LocalHttpResponse
    {
        if (rt.homeserver.oauth_user_code_attempts.record_wrong(client_key, now_ms))
        {
            log_oauth("oauth.device.throttled",
                      {
                          {"client_key", std::string{client_key}, false}
            },
                      observability::LogEventSeverity::warning);
        }
        return link_page_response(status_bad_request, std::nullopt,
                                  oauth::HtmlText{"That code is not right, or it has expired. Check the code your "
                                                  "device shows and try again."});
    }

    // A wait in milliseconds as retry_after_seconds takes it; the device grant's waits are at most ten minutes.
    [[nodiscard]] auto clamped_retry_ms(std::uint64_t retry_after_ms) noexcept -> std::uint32_t
    {
        return static_cast<std::uint32_t>(
            std::min<std::uint64_t>(retry_after_ms, std::numeric_limits<std::uint32_t>::max()));
    }

    // `POST /_merovingian/oauth2/link`: the code the user typed (ADR-0805, ADR-0806).
    [[nodiscard]] auto handle_link_post(ClientServerRuntime& rt, LocalHttpRequest const& request) -> LocalHttpResponse
    {
        auto& runtime = rt.homeserver;
        auto base = oauth::OAuthBaseUrl::read(runtime.config.server().public_baseurl);
        auto const* base_url = std::get_if<oauth::OAuthBaseUrl>(&base);
        if (base_url == nullptr)
        {
            return link_unavailable_page();
        }
        // Before anything is read: another site's post is refused whatever it carries (ADR-0784).
        if (!oauth::form_post_origin_is_accepted(*base_url, single_request_header(request, "Origin"),
                                                 single_request_header(request, "Sec-Fetch-Site")))
        {
            return oauth_error_page_response(status_forbidden, oauth::HtmlText{"Form refused"},
                                             oauth::HtmlText{"This form was not sent from a page of this server."});
        }
        auto const content_type = single_request_header(request, "Content-Type");
        if (!content_type.has_value() || !oauth::page_form_content_type_is_accepted(*content_type))
        {
            return oauth_error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                             oauth::HtmlText{"This form could not be read."});
        }
        auto parsed = core::FormFields::parse(request.body);
        auto const* fields = std::get_if<core::FormFields>(&parsed);
        if (fields == nullptr)
        {
            return oauth_error_page_response(status_bad_request, oauth::HtmlText{"Form refused"},
                                             oauth::HtmlText{"This form could not be read."});
        }
        // A post without the page's cookie is not a guess: it is not counted, and the page is sent again with one.
        auto browser_token = request_secret_cookie(request, oauth_browser_cookie_name);
        if (!browser_token.has_value())
        {
            auto const cookie = browser_cookie(request);
            if (!cookie.has_value())
            {
                return link_unavailable_page();
            }
            auto response =
                link_page_response(status_bad_request, std::nullopt,
                                   oauth::HtmlText{"Your browser did not send the cookie this page sets. Enter the "
                                                   "code again; if this repeats, allow cookies for this server."});
            response.headers.emplace_back("Set-Cookie", cookie->set_cookie);
            return response;
        }
        auto const client_key = rate_limit_client_key(request, runtime.config.server());
        auto const now_ms = oauth_device_clock_ms(runtime);
        // The throttle comes before the lookup: a blocked address is not told whether its code is right.
        if (auto const blocked = runtime.oauth_user_code_attempts.blocked_for_ms(client_key, now_ms);
            blocked.has_value())
        {
            auto const seconds = retry_after_seconds(clamped_retry_ms(*blocked));
            auto response = link_page_response(
                status_too_many_requests, std::nullopt,
                oauth::HtmlText{"Too many wrong codes were entered from your network. Wait a few minutes and try "
                                "again."});
            response.headers.emplace_back("Retry-After", std::to_string(seconds));
            return response;
        }
        auto const typed = fields->find(oauth::user_code_field.view());
        auto const user_code = typed.has_value() ? oauth::normalise_user_code(*typed) : std::nullopt;
        if (!user_code.has_value())
        {
            return wrong_code(rt, client_key, now_ms);
        }
        auto attached = runtime.oauth_device_authorisations.attach(*user_code, *browser_token, now_ms);
        if (std::holds_alternative<DeviceAuthorisationStore::NotFound>(attached))
        {
            return wrong_code(rt, client_key, now_ms);
        }
        if (auto const* busy = std::get_if<DeviceAuthorisationStore::Busy>(&attached); busy != nullptr)
        {
            auto const seconds = retry_after_seconds(clamped_retry_ms(busy->retry_after_ms));
            auto response = link_page_response(
                status_conflict, std::nullopt,
                oauth::HtmlText{"This code is being used to sign in from another browser right now. Try again in two "
                                "minutes."});
            response.headers.emplace_back("Retry-After", std::to_string(seconds));
            return response;
        }
        auto& hold = std::get<DeviceAuthorisationStore::Attached>(attached);
        auto authorisation = PendingAuthorisation{};
        authorisation.kind = PendingAuthorisationKind::device_authorization;
        authorisation.client_id = hold.authorisation.client_id;
        authorisation.device_id = hold.authorisation.device_id;
        authorisation.scope = hold.authorisation.scope;
        authorisation.device_authorisation_key = hold.key;
        authorisation.device_attachment = hold.attachment;
        auto start = start_sign_in(rt, request, std::move(authorisation), FirstPage::login);
        if (!start.started)
        {
            runtime.oauth_device_authorisations.release(hold.key, hold.attachment);
        }
        return std::move(start.response);
    }

} // namespace

auto handle_oauth_link(ClientServerRuntime& runtime, LocalHttpRequest const& request) -> LocalHttpResponse
{
    if (request.method == "POST")
    {
        return handle_link_post(runtime, request);
    }
    return handle_link_get(request);
}

auto handle_login_hand_off(ClientServerRuntime& rt, LocalHttpRequest const& request) -> LocalHttpResponse
{
    auto& runtime = rt.homeserver;
    auto parsed = core::FormFields::parse_query(request_target_query(request.target));
    auto const* fields = std::get_if<core::FormFields>(&parsed);
    if (fields == nullptr)
    {
        log_hand_off("oauth.hand_off.refused", {}, observability::LogEventSeverity::debug);
        return bad_request_page(oauth::HtmlText{"The request is malformed. Return to the application and try again."});
    }
    auto const redirect_url = fields->find("redirectUrl");
    if (!redirect_url.has_value() || redirect_url->empty())
    {
        log_hand_off("oauth.hand_off.refused", {}, observability::LogEventSeverity::debug);
        return bad_request_page(oauth::HtmlText{"The application did not say where to return after the sign-in. "
                                                "Return to the application and try again."});
    }
    // Read here only to refuse; the entry keeps the text and every later step reads it again (ADR-0802).
    if (!oauth::hand_off_redirect_target(*redirect_url, runtime.config.server().oauth.hand_off_redirect_allowlist)
             .has_value())
    {
        log_hand_off("oauth.hand_off.refused", {}, observability::LogEventSeverity::debug);
        return bad_request_page(oauth::HtmlText{"The application asked to return to an address this server does not "
                                                "send sign-ins to. Return to the application and try again."});
    }
    // Spec `GET /login/sso/redirect`: `action` is `login` or `register`; anything else, or none, is a login.
    auto first_page = FirstPage::login;
    if (fields->find("action") == std::optional<std::string_view>{"register"})
    {
        first_page = registration_enabled(runtime) ? FirstPage::registration : FirstPage::registration_closed;
    }
    auto authorisation = PendingAuthorisation{};
    authorisation.kind = PendingAuthorisationKind::login_token_hand_off;
    authorisation.redirect_uri = std::string{*redirect_url};
    authorisation.create_account = first_page != FirstPage::login;
    auto start = start_sign_in(rt, request, std::move(authorisation), first_page);
    log_hand_off(start.started ? "oauth.hand_off.started" : "oauth.hand_off.refused", {},
                 observability::LogEventSeverity::debug);
    return std::move(start.response);
}

auto handle_oauth_authorize(ClientServerRuntime& runtime, LocalHttpRequest const& request) -> LocalHttpResponse
{
    if (request.method == "POST")
    {
        return handle_post(runtime, request);
    }
    return handle_get(runtime, request);
}

} // namespace merovingian::homeserver
