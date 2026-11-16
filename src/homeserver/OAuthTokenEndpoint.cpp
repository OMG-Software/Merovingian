// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthTokenEndpoint.hpp"

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/FormFields.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/AuthorizationCodeRedemption.hpp"
#include "merovingian/homeserver/AuthorizationCodeStore.hpp"
#include "merovingian/homeserver/ClientDeviceSessions.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
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
#include <tuple>
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

    // Logs a refused token request: the grant type, the wire error and the client ID when one was sent. Never the
    // code, the verifier, a token or any other value the request carried.
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
        auto const refuse = [&](std::uint16_t status, std::string_view error_code,
                                std::string_view description) -> LocalHttpResponse {
            log_refused(grant_type, error_code, client_id.value_or(std::string_view{}));
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

        auto request = OAuthGrantRequest{};
        request.user_id = grant.user_id;
        request.device_id = grant.device_id;
        request.client_id = grant.client_id;
        request.scope = grant.scope;
        request.display_name = device_display_name(rt, *client);
        request.created_at_ms = runtime.oauth_codes.next_session_created_at_ms(now_ms);
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
        // Names the row this code produced, so a replay ends it and nothing else. The code is held: nothing above
        // released runtime.mutex, so it cannot have expired from under the redemption.
        std::ignore = runtime.oauth_codes.record_issued_session(*code, request.created_at_ms, oauth_wall_clock_ms());
        remember_signed_in_device(rt, session.user_id, session.device_id, request.display_name,
                                  SignedInDevice::new_session);
        return token_answer(session, oauth_expires_in(runtime), grant.scope);
    }

    [[nodiscard]] auto refresh_token_grant(ClientServerRuntime& rt, core::FormFields const& fields) -> LocalHttpResponse
    {
        constexpr auto grant_type = oauth::grant_type_refresh_token;
        auto& runtime = rt.homeserver;
        auto const client_id = fields.find("client_id");
        auto const refresh_token = fields.find("refresh_token");
        auto const refuse = [&](std::uint16_t status, std::string_view error_code,
                                std::string_view description) -> LocalHttpResponse {
            log_refused(grant_type, error_code, client_id.value_or(std::string_view{}));
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
        // As POST /refresh does: the runtime's device list is healed after a restart, nothing is announced.
        remember_signed_in_device(rt, session.user_id, session.device_id, session.device_id,
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
    log_refused({}, oauth::error_unsupported_grant_type, {});
    return oauth_error_response(status_bad_request, oauth::error_unsupported_grant_type,
                                "The grant_type is not supported.");
}

} // namespace merovingian::homeserver
