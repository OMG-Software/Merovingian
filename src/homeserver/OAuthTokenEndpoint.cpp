// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthTokenEndpoint.hpp"

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/FormFields.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/AuthorizationCodeRedemption.hpp"
#include "merovingian/homeserver/AuthorizationCodeStore.hpp"
#include "merovingian/homeserver/ClientDeviceSessions.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/DeviceAuthorisationStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/OAuthClientCredentials.hpp"
#include "merovingian/homeserver/OAuthClientRegistration.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"
#include "merovingian/homeserver/OAuthGrantRequest.hpp"
#include "merovingian/homeserver/OAuthJsonResponse.hpp"
#include "merovingian/homeserver/PasswordLoginVerification.hpp"
#include "merovingian/homeserver/RequestHeaders.hpp"
#include "merovingian/homeserver/SessionRefreshResult.hpp"
#include "merovingian/homeserver/SignedInDevice.hpp"
#include "merovingian/homeserver/StoredDeviceDisplayName.hpp"
#include "merovingian/oauth/AccessTokenLifetime.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"
#include "merovingian/oauth/FormContentType.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/Pkce.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    constexpr auto status_ok = std::uint16_t{200U};
    constexpr auto status_bad_request = std::uint16_t{400U};
    constexpr auto status_server_error = std::uint16_t{500U};
    constexpr auto first_server_error_status = std::uint16_t{500U};

    // Logs a refused token request: the grant type, the wire error and the client ID once it names a registered client
    // (empty before then, so a caller cannot write text of its choosing into the log). Never the code, the verifier, a
    // token or any other value the request carried.
    auto log_refused(std::string_view grant_type, std::string_view error_code, std::string_view client_id) -> void
    {
        auto fields = std::vector<observability::StructuredLogField>{
            {"grant_type", std::string{grant_type}, false},
            {"error",      std::string{error_code}, false}
        };
        if (!client_id.empty())
        {
            fields.push_back({"client_id", std::string{client_id}, false});
        }
        observability::log_diagnostic("oauth", "oauth.token.refused", std::move(fields),
                                      observability::LogEventSeverity::debug);
    }

    [[nodiscard]] auto token_answer(SessionRefreshResult const& session, std::int64_t expires_in,
                                    std::string_view scope) -> LocalHttpResponse
    {
        auto object = canonicaljson::Object{};
        object.push_back(canonicaljson::make_member("access_token", canonicaljson::Value{session.access_token}));
        object.push_back(canonicaljson::make_member("expires_in", canonicaljson::Value{expires_in}));
        object.push_back(canonicaljson::make_member("refresh_token", canonicaljson::Value{session.refresh_token}));
        object.push_back(canonicaljson::make_member("scope", canonicaljson::Value{std::string{scope}}));
        object.push_back(canonicaljson::make_member("token_type", canonicaljson::Value{std::string{"Bearer"}}));
        return oauth_json_response(status_ok, canonicaljson::Value{std::move(object)});
    }

    [[nodiscard]] auto oauth_expires_in(HomeserverRuntime const& runtime) -> std::int64_t
    {
        return oauth::expires_in_seconds(
            oauth::access_token_lifetime_ms(runtime.config.security().access_token_lifetime_ms));
    }

    // A replayed code (ADR-0792): the session its first redemption produced is ended, and only it. The device's
    // current `oauth_sessions` row must be the very one that redemption wrote, named by its client and its
    // process-unique `created_at_ms`; a row written since (a later grant on the same device) is left alone.
    auto end_replayed_session(ClientServerRuntime& rt, AuthorizationCodeRedemption const& redemption) -> void
    {
        auto& runtime = rt.homeserver;
        auto ended = false;
        if (redemption.session_created_at_ms.has_value())
        {
            auto const* const row = database::find_oauth_session(runtime.database.persistent_store, redemption.user_id,
                                                                 redemption.device_id);
            if (row != nullptr && row->client_id == redemption.client_id &&
                row->created_at_ms == *redemption.session_created_at_ms)
            {
                ended =
                    end_device_session_and_announce(rt, redemption.user_id, redemption.device_id, "oauth.code.replayed")
                        .ok;
            }
        }
        observability::log_diagnostic("oauth", "oauth.code.replayed",
                                      {
                                          {"client_id",     redemption.client_id,     false},
                                          {"user_id",       redemption.user_id,       false},
                                          {"device_id",     redemption.device_id,     false},
                                          {"session_ended", ended ? "true" : "false", false}
        },
                                      observability::LogEventSeverity::warning);
    }

    [[nodiscard]] auto device_display_name(ClientServerRuntime const& rt, oauth::ClientMetadata const& client)
        -> std::string
    {
        auto const& name = client.client_name();
        if (!name.has_value() || name->size() > rt.limits.max_device_display_name_bytes)
        {
            return {};
        }
        return *name;
    }

    [[nodiscard]] auto authorization_code_grant(ClientServerRuntime& rt, core::FormFields const& fields)
        -> LocalHttpResponse
    {
        constexpr auto grant_type = oauth::grant_type_authorization_code;
        auto& runtime = rt.homeserver;
        auto const client_id = fields.find("client_id");
        auto const code = fields.find("code");
        auto const redirect_uri = fields.find("redirect_uri");
        auto const verifier = fields.find("code_verifier");
        // Set once the client ID names a registered client; a refusal before then logs no client ID.
        auto registered_client_id = std::string_view{};
        auto const refuse = [&](std::uint16_t status, std::string_view error_code,
                                std::string_view description) -> LocalHttpResponse {
            log_refused(grant_type, error_code, registered_client_id);
            return oauth_error_response(status, error_code, description);
        };
        if (!client_id.has_value() || !code.has_value() || !redirect_uri.has_value() || !verifier.has_value())
        {
            return refuse(status_bad_request, oauth::error_invalid_request,
                          "The request lacks client_id, code, redirect_uri or code_verifier.");
        }
        auto const client = find_registered_oauth_client(runtime, *client_id);
        if (!client.has_value())
        {
            return refuse(status_bad_request, oauth::error_invalid_client, "The client is not registered.");
        }
        registered_client_id = *client_id;
        if (!client->has_grant_type(grant_type))
        {
            return refuse(status_bad_request, oauth::error_unauthorized_client,
                          "The client is not registered for the authorization_code grant.");
        }
        if (!oauth::pkce_verifier_is_valid(*verifier))
        {
            return refuse(status_bad_request, oauth::error_invalid_request, "The code_verifier is malformed.");
        }

        auto const now_ms = oauth_wall_clock_ms();
        auto const redemption = runtime.oauth_codes.redeem(*code, now_ms);
        if (redemption.outcome == AuthorizationCodeRedemption::Outcome::replayed)
        {
            end_replayed_session(rt, redemption);
            return refuse(status_bad_request, oauth::error_invalid_grant, "The authorization code was already used.");
        }
        if (redemption.outcome != AuthorizationCodeRedemption::Outcome::fresh)
        {
            return refuse(status_bad_request, oauth::error_invalid_grant,
                          "The authorization code is invalid or expired.");
        }
        // The code is spent from here, whatever the outcome (RFC 6749 section 4.1.2: single use).
        auto const& grant = redemption.grant;
        if (grant.client_id != *client_id || grant.redirect_uri != *redirect_uri ||
            !oauth::pkce_s256_matches(*verifier, grant.code_challenge))
        {
            return refuse(status_bad_request, oauth::error_invalid_grant,
                          "The authorization code was not issued for this request.");
        }
        if (account_sign_in_gate(runtime, grant.user_id, grant.device_id) !=
            PasswordLoginVerification::Outcome::verified)
        {
            return refuse(status_bad_request, oauth::error_invalid_grant, "The account cannot sign in.");
        }
        // The password that signed in must still be the account's (ADR-0807); the code is spent either way.
        if (!user_credential_stamp_matches(runtime, grant.user_id, grant.credential_stamp))
        {
            return refuse(status_bad_request, oauth::error_invalid_grant, "The authorization is no longer valid.");
        }

        auto request = OAuthGrantRequest{};
        request.user_id = grant.user_id;
        request.device_id = grant.device_id;
        request.client_id = grant.client_id;
        request.scope = grant.scope;
        request.display_name = device_display_name(rt, *client);
        request.created_at_ms = runtime.oauth_codes.next_session_created_at_ms(now_ms);
        // Names the row this code is about to produce, so a replay ends it and nothing else (ADR-0792). Recorded
        // before the grant commits and at the redemption's own instant, at which the code is held, so nothing that
        // can fail follows the commit. Should the grant then fail, the value names no row: every value is
        // new, so a replay ends nothing.
        if (!runtime.oauth_codes.record_issued_session(*code, request.created_at_ms, now_ms))
        {
            return refuse(status_server_error, oauth::error_server_error, "The server could not complete the grant.");
        }
        auto const session = grant_oauth_session(runtime, request);
        if (!session.ok)
        {
            if (session.status >= first_server_error_status)
            {
                return refuse(status_server_error, oauth::error_server_error,
                              "The server could not complete the grant.");
            }
            return refuse(status_bad_request, oauth::error_invalid_grant, "The session cannot be granted.");
        }
        remember_signed_in_device(rt, session.user_id, session.device_id, request.display_name,
                                  SignedInDevice::new_session);
        return token_answer(session, oauth_expires_in(runtime), grant.scope);
    }

    // RFC 8628 section 3.4 and 3.5 (ADR-0804): every refusal is 400 with the section's code, except a failed
    // storage write (500). The device code is spent once the store hands back an approval, whatever follows.
    [[nodiscard]] auto device_code_grant(ClientServerRuntime& rt, core::FormFields const& fields) -> LocalHttpResponse
    {
        constexpr auto grant_type = oauth::grant_type_device_code;
        auto& runtime = rt.homeserver;
        auto const client_id = fields.find("client_id");
        auto const device_code = fields.find("device_code");
        // Set once the client ID names a registered client; a refusal before then logs no client ID.
        auto registered_client_id = std::string_view{};
        auto const refuse = [&](std::uint16_t status, std::string_view error_code,
                                std::string_view description) -> LocalHttpResponse {
            log_refused(grant_type, error_code, registered_client_id);
            return oauth_error_response(status, error_code, description);
        };
        // RFC 6749 section 3.1: a parameter sent without a value is treated as omitted.
        if (!client_id.has_value() || client_id->empty() || !device_code.has_value() || device_code->empty())
        {
            return refuse(status_bad_request, oauth::error_invalid_request,
                          "The request lacks client_id or device_code.");
        }
        auto const client = find_registered_oauth_client(runtime, *client_id);
        if (!client.has_value())
        {
            return refuse(status_bad_request, oauth::error_invalid_client, "The client is not registered.");
        }
        registered_client_id = *client_id;
        if (!client->has_grant_type(grant_type))
        {
            return refuse(status_bad_request, oauth::error_unauthorized_client,
                          "The client is not registered for the device code grant.");
        }
        auto const polled =
            runtime.oauth_device_authorisations.poll(*device_code, *client_id, oauth_device_clock_ms(runtime));
        using PollOutcome = DeviceAuthorisationStore::PollOutcome;
        switch (polled.outcome)
        {
        case PollOutcome::expired_token:
            return refuse(status_bad_request, oauth::error_expired_token,
                          "The device code is unknown, expired or already used.");
        case PollOutcome::wrong_client:
            return refuse(status_bad_request, oauth::error_invalid_grant,
                          "The device code was not issued to this client.");
        case PollOutcome::access_denied:
            return refuse(status_bad_request, oauth::error_access_denied, "The user denied the request.");
        case PollOutcome::slow_down:
            return refuse(status_bad_request, oauth::error_slow_down, "Polling too often; wait longer between polls.");
        case PollOutcome::authorization_pending:
            // Not logged: a device polls every few seconds until the user answers.
            return oauth_error_response(status_bad_request, oauth::error_authorization_pending,
                                        "The user has not answered yet.");
        case PollOutcome::approved:
            break;
        }
        if (!polled.authorisation.has_value())
        {
            return refuse(status_bad_request, oauth::error_expired_token,
                          "The device code is unknown, expired or already used.");
        }
        auto const& approved = *polled.authorisation;
        if (account_sign_in_gate(runtime, approved.user_id, approved.device_id) !=
            PasswordLoginVerification::Outcome::verified)
        {
            return refuse(status_bad_request, oauth::error_invalid_grant, "The account cannot sign in.");
        }
        // The password that approved must still be the account's (ADR-0807); the device code is spent either way.
        if (!user_credential_stamp_matches(runtime, approved.user_id, approved.credential_stamp))
        {
            return refuse(status_bad_request, oauth::error_invalid_grant, "The authorization is no longer valid.");
        }
        auto request = OAuthGrantRequest{};
        request.user_id = approved.user_id;
        request.device_id = approved.device_id;
        request.client_id = approved.client_id;
        request.scope = approved.scope;
        request.display_name = device_display_name(rt, *client);
        request.created_at_ms = runtime.oauth_codes.next_session_created_at_ms(oauth_wall_clock_ms());
        auto const session = grant_oauth_session(runtime, request);
        if (!session.ok)
        {
            if (session.status >= first_server_error_status)
            {
                return refuse(status_server_error, oauth::error_server_error,
                              "The server could not complete the grant.");
            }
            return refuse(status_bad_request, oauth::error_invalid_grant, "The session cannot be granted.");
        }
        remember_signed_in_device(rt, session.user_id, session.device_id, request.display_name,
                                  SignedInDevice::new_session);
        return token_answer(session, oauth_expires_in(runtime), approved.scope);
    }

    [[nodiscard]] auto refresh_token_grant(ClientServerRuntime& rt, core::FormFields const& fields) -> LocalHttpResponse
    {
        constexpr auto grant_type = oauth::grant_type_refresh_token;
        auto& runtime = rt.homeserver;
        auto const client_id = fields.find("client_id");
        auto const refresh_token = fields.find("refresh_token");
        // Set once the client ID names a registered client; a refusal before then logs no client ID.
        auto registered_client_id = std::string_view{};
        auto const refuse = [&](std::uint16_t status, std::string_view error_code,
                                std::string_view description) -> LocalHttpResponse {
            log_refused(grant_type, error_code, registered_client_id);
            return oauth_error_response(status, error_code, description);
        };
        if (!client_id.has_value() || !refresh_token.has_value())
        {
            return refuse(status_bad_request, oauth::error_invalid_request,
                          "The request lacks client_id or refresh_token.");
        }
        auto const client = find_registered_oauth_client(runtime, *client_id);
        if (!client.has_value())
        {
            return refuse(status_bad_request, oauth::error_invalid_client, "The client is not registered.");
        }
        registered_client_id = *client_id;
        if (!client->has_grant_type(grant_type))
        {
            return refuse(status_bad_request, oauth::error_unauthorized_client,
                          "The client is not registered for the refresh_token grant.");
        }
        auto const session = refresh_local_session(runtime, *refresh_token, *client_id);
        if (!session.ok)
        {
            if (session.status >= first_server_error_status)
            {
                return refuse(status_server_error, oauth::error_server_error,
                              "The server could not refresh the session.");
            }
            return refuse(status_bad_request, oauth::error_invalid_grant, "The refresh token is invalid.");
        }
        // The runtime's device list is healed after a restart, with the device's stored display name; nothing is
        // announced.
        remember_signed_in_device(rt, session.user_id, session.device_id,
                                  stored_device_display_name(runtime, session.user_id, session.device_id),
                                  SignedInDevice::refreshed_session);
        auto const* const row =
            database::find_oauth_session(runtime.database.persistent_store, session.user_id, session.device_id);
        auto const scope = row != nullptr ? row->scope : std::string{};
        return token_answer(session, oauth_expires_in(runtime), scope);
    }

} // namespace

auto handle_oauth_token(ClientServerRuntime& runtime, LocalHttpRequest const& request) -> LocalHttpResponse
{
    if (!oauth::api_form_content_type_is_accepted(request_header(request, "Content-Type")))
    {
        log_refused({}, oauth::error_invalid_request, {});
        return oauth_error_response(status_bad_request, oauth::error_invalid_request,
                                    "The body must be application/x-www-form-urlencoded.");
    }
    auto parsed = core::FormFields::parse(request.body);
    auto const* const fields = std::get_if<core::FormFields>(&parsed);
    if (fields == nullptr)
    {
        log_refused({}, oauth::error_invalid_request, {});
        return oauth_error_response(status_bad_request, oauth::error_invalid_request, "The body is malformed.");
    }
    // The parsed fields hold the code, the verifier or the refresh token; FormFields wipes them when `parsed` ends.
    if (auto credentials_refusal = oauth_client_credentials_refusal(request, *fields); credentials_refusal.has_value())
    {
        log_refused({}, oauth::error_invalid_client, {});
        return std::move(*credentials_refusal);
    }
    auto const grant_type = fields->find("grant_type");
    if (!grant_type.has_value())
    {
        log_refused({}, oauth::error_invalid_request, {});
        return oauth_error_response(status_bad_request, oauth::error_invalid_request, "The request lacks grant_type.");
    }
    if (*grant_type == oauth::grant_type_authorization_code)
    {
        return authorization_code_grant(runtime, *fields);
    }
    if (*grant_type == oauth::grant_type_refresh_token)
    {
        return refresh_token_grant(runtime, *fields);
    }
    // Served only with the device grant on (ADR-0804); off, the grant type is as unknown as any other.
    if (*grant_type == oauth::grant_type_device_code && runtime.homeserver.config.server().oauth.device_grant_enabled)
    {
        return device_code_grant(runtime, *fields);
    }
    log_refused({}, oauth::error_unsupported_grant_type, {});
    return oauth_error_response(status_bad_request, oauth::error_unsupported_grant_type,
                                "The grant_type is not supported.");
}

} // namespace merovingian::homeserver
