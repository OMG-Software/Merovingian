// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthRevocation.hpp"

#include "merovingian/core/FormFields.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthSession.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientDeviceSessions.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalSession.hpp"
#include "merovingian/homeserver/OAuthClientCredentials.hpp"
#include "merovingian/homeserver/OAuthJsonResponse.hpp"
#include "merovingian/homeserver/RequestHeaders.hpp"
#include "merovingian/oauth/FormContentType.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <cstdint>
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

    // Logs a refused revocation request by its wire error only: the request carried a token.
    auto log_refused(std::string_view error_code) -> void
    {
        observability::log_diagnostic("oauth", "oauth.revocation.refused",
                                      {
                                          {"error", std::string{error_code}, false}
        },
                                      observability::LogEventSeverity::debug);
    }

} // namespace

auto handle_oauth_revoke(ClientServerRuntime& runtime, LocalHttpRequest const& request) -> LocalHttpResponse
{
    if (!oauth::api_form_content_type_is_accepted(request_header(request, "Content-Type")))
    {
        log_refused(oauth::error_invalid_request);
        return oauth_error_response(status_bad_request, oauth::error_invalid_request,
                                    "The body must be application/x-www-form-urlencoded.");
    }
    // The parsed fields hold the token; FormFields wipes them when `parsed` ends.
    auto parsed = core::FormFields::parse(request.body);
    auto const* const fields = std::get_if<core::FormFields>(&parsed);
    if (fields == nullptr)
    {
        log_refused(oauth::error_invalid_request);
        return oauth_error_response(status_bad_request, oauth::error_invalid_request, "The body is malformed.");
    }
    if (auto credentials_refusal = oauth_client_credentials_refusal(request, *fields); credentials_refusal.has_value())
    {
        log_refused(oauth::error_invalid_client);
        return std::move(*credentials_refusal);
    }
    auto const token = fields->find("token");
    if (!token.has_value())
    {
        log_refused(oauth::error_invalid_request);
        return oauth_error_response(status_bad_request, oauth::error_invalid_request, "The request lacks token.");
    }

    auto& homeserver = runtime.homeserver;
    auto const session = revocable_session_of_token(homeserver, *token);
    if (!session.has_value())
    {
        // RFC 7009 section 2.2: a token that is invalid, expired or already revoked is answered 200 all the same.
        return oauth_empty_response(status_ok);
    }
    auto const* const oauth_row =
        database::find_oauth_session(homeserver.database.persistent_store, session->user_id, session->device_id);
    auto const client_id = oauth_row != nullptr ? oauth_row->client_id : std::string{};
    auto const ended =
        end_device_session_and_announce(runtime, session->user_id, session->device_id, "oauth.session.revoked");
    if (!ended.ok)
    {
        log_refused(oauth::error_server_error);
        return oauth_error_response(status_server_error, oauth::error_server_error,
                                    "The server could not revoke the session.");
    }
    auto fields_logged = std::vector<observability::StructuredLogField>{
        {"user_id",   session->user_id,   false},
        {"device_id", session->device_id, false}
    };
    if (!client_id.empty())
    {
        fields_logged.push_back({"client_id", client_id, false});
    }
    observability::log_diagnostic("oauth", "oauth.revocation.accepted", std::move(fields_logged),
                                  observability::LogEventSeverity::info);
    return oauth_empty_response(status_ok);
}

} // namespace merovingian::homeserver
