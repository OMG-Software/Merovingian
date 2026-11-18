// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthDeviceAuthorization.hpp"

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/FormFields.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/DeviceAuthorisationStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/OAuthClientCredentials.hpp"
#include "merovingian/homeserver/OAuthClientRegistration.hpp"
#include "merovingian/homeserver/OAuthClock.hpp"
#include "merovingian/homeserver/OAuthJsonResponse.hpp"
#include "merovingian/homeserver/RequestHeaders.hpp"
#include "merovingian/oauth/ClientMetadata.hpp"
#include "merovingian/oauth/FormContentType.hpp"
#include "merovingian/oauth/GrantedScope.hpp"
#include "merovingian/oauth/OAuthBaseUrl.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/OAuthPaths.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"
#include "merovingian/oauth/ScopeParser.hpp"
#include "merovingian/oauth/UserCode.hpp"
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
    constexpr auto status_unavailable = std::uint16_t{503U};
    constexpr auto ms_per_second = std::uint64_t{1000U};

    // Logs a refused device authorization request: the wire error and the client ID once it names a registered client.
    // Never a value the request carried beyond that.
    auto log_refused(std::string_view error_code, std::string_view client_id) -> void
    {
        auto fields = std::vector<observability::StructuredLogField>{
            {"error", std::string{error_code}, false}
        };
        if (!client_id.empty())
        {
            fields.push_back({"client_id", std::string{client_id}, false});
        }
        observability::log_diagnostic("oauth", "oauth.device.refused", std::move(fields),
                                      observability::LogEventSeverity::debug);
    }

    [[nodiscard]] auto seconds_of(std::uint64_t milliseconds) -> std::int64_t
    {
        return static_cast<std::int64_t>(milliseconds / ms_per_second);
    }

} // namespace

auto handle_oauth_device_authorization(ClientServerRuntime& rt, LocalHttpRequest const& request) -> LocalHttpResponse
{
    auto& runtime = rt.homeserver;
    if (!oauth::api_form_content_type_is_accepted(request_header(request, "Content-Type")))
    {
        log_refused(oauth::error_invalid_request, {});
        return oauth_error_response(status_bad_request, oauth::error_invalid_request,
                                    "The body must be application/x-www-form-urlencoded.");
    }
    auto parsed = core::FormFields::parse(request.body);
    auto const* const fields = std::get_if<core::FormFields>(&parsed);
    if (fields == nullptr)
    {
        log_refused(oauth::error_invalid_request, {});
        return oauth_error_response(status_bad_request, oauth::error_invalid_request, "The body is malformed.");
    }
    if (auto credentials_refusal = oauth_client_credentials_refusal(request, *fields); credentials_refusal.has_value())
    {
        log_refused(oauth::error_invalid_client, {});
        return std::move(*credentials_refusal);
    }
    auto const client_id = fields->find("client_id");
    if (!client_id.has_value() || client_id->empty())
    {
        log_refused(oauth::error_invalid_request, {});
        return oauth_error_response(status_bad_request, oauth::error_invalid_request, "The request lacks client_id.");
    }
    auto const client = find_registered_oauth_client(runtime, *client_id);
    if (!client.has_value())
    {
        // Not the client ID: it names no registered client, so it is text of the caller's choosing.
        log_refused(oauth::error_invalid_client, {});
        return oauth_error_response(status_bad_request, oauth::error_invalid_client, "The client is not registered.");
    }
    if (!client->has_grant_type(oauth::grant_type_device_code))
    {
        log_refused(oauth::error_unauthorized_client, *client_id);
        return oauth_error_response(status_bad_request, oauth::error_unauthorized_client,
                                    "The client is not registered for the device code grant.");
    }
    auto scope = oauth::parse_scope(fields->find("scope").value_or(std::string_view{}));
    if (auto const* refused = std::get_if<oauth::OAuthRefusal>(&scope); refused != nullptr)
    {
        log_refused(refused->error_code, *client_id);
        return oauth_error_response(status_bad_request, *refused);
    }
    auto const& granted = std::get<oauth::GrantedScope>(scope);
    auto base = oauth::OAuthBaseUrl::read(runtime.config.server().public_baseurl);
    auto const* const base_url = std::get_if<oauth::OAuthBaseUrl>(&base);
    if (base_url == nullptr)
    {
        log_refused(oauth::error_server_error, *client_id);
        return oauth_error_response(status_server_error, oauth::error_server_error,
                                    "The server is not configured for the device code grant.");
    }

    auto created = runtime.oauth_device_authorisations.create(*client_id, granted.scope, granted.device_id,
                                                              rate_limit_client_key(request, runtime.config.server()),
                                                              oauth_device_clock_ms(runtime));
    if (auto const* refusal = std::get_if<DeviceAuthorisationStore::Refusal>(&created); refusal != nullptr)
    {
        if (*refusal == DeviceAuthorisationStore::Refusal::secret_unavailable)
        {
            log_refused(oauth::error_server_error, *client_id);
            return oauth_error_response(status_server_error, oauth::error_server_error,
                                        "The server could not start the device authorisation.");
        }
        log_refused(oauth::error_temporarily_unavailable, *client_id);
        return oauth_error_response(status_unavailable, oauth::error_temporarily_unavailable,
                                    "Too many device sign-ins are in progress. Try again in a few minutes.");
    }
    auto const& started = std::get<DeviceAuthorisationStore::Started>(created);
    auto const shown_code = oauth::display_user_code(started.user_code);
    auto const verification_uri = base_url->url(oauth::link_path);
    // The shown code has only capital consonants and a dash, all unreserved: it needs no percent-encoding.
    auto const verification_uri_complete = verification_uri + "?user_code=" + shown_code;

    observability::log_diagnostic("oauth", "oauth.device.started",
                                  {
                                      {"client_id", std::string{*client_id}, false}
    },
                                  observability::LogEventSeverity::info);

    auto object = canonicaljson::Object{};
    object.push_back(canonicaljson::make_member("device_code", canonicaljson::Value{started.device_code}));
    object.push_back(canonicaljson::make_member("expires_in", canonicaljson::Value{seconds_of(started.expires_in_ms)}));
    object.push_back(canonicaljson::make_member("interval", canonicaljson::Value{seconds_of(started.interval_ms)}));
    object.push_back(canonicaljson::make_member("user_code", canonicaljson::Value{shown_code}));
    object.push_back(canonicaljson::make_member("verification_uri", canonicaljson::Value{verification_uri}));
    object.push_back(
        canonicaljson::make_member("verification_uri_complete", canonicaljson::Value{verification_uri_complete}));
    return oauth_json_response(status_ok, canonicaljson::Value{std::move(object)});
}

} // namespace merovingian::homeserver
