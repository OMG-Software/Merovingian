// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthClientRegistration.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/Error.hpp"
#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/crypto/OAuthClientId.hpp"
#include "merovingian/crypto/TokenKey.hpp"
#include "merovingian/database/OAuthClientStoreResult.hpp"
#include "merovingian/database/OAuthStore.hpp"
#include "merovingian/database/PersistentOAuthClient.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/OAuthJsonResponse.hpp"
#include "merovingian/homeserver/RetentionSweep.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
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

    [[nodiscard]] auto wall_clock_ms() -> std::uint64_t
    {
        auto const now =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
        return now.count() < 0 ? std::uint64_t{0U} : static_cast<std::uint64_t>(now.count());
    }

    [[nodiscard]] auto refusal(std::string_view code, core::ErrorCode kind, std::string message) -> oauth::OAuthRefusal
    {
        return oauth::OAuthRefusal{
            std::string{code},
            core::Error{kind, std::move(message)}
        };
    }

    [[nodiscard]] auto invalid_metadata(std::string message) -> LocalHttpResponse
    {
        return oauth_error_response(
            400U, refusal(oauth::error_invalid_client_metadata, core::ErrorCode::parse_failure, std::move(message)));
    }

    [[nodiscard]] auto server_error(std::string message) -> LocalHttpResponse
    {
        return oauth_error_response(
            500U, refusal(oauth::error_server_error, core::ErrorCode::internal_failure, std::move(message)));
    }

    [[nodiscard]] auto ascii_lower(char value) noexcept -> char
    {
        return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
    }

    [[nodiscard]] auto equals_ignoring_ascii_case(std::string_view left, std::string_view right) noexcept -> bool
    {
        if (left.size() != right.size())
        {
            return false;
        }
        for (auto index = std::size_t{0U}; index < left.size(); ++index)
        {
            if (ascii_lower(left[index]) != ascii_lower(right[index]))
            {
                return false;
            }
        }
        return true;
    }

    [[nodiscard]] auto trim_whitespace(std::string_view text) noexcept -> std::string_view
    {
        while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
        {
            text.remove_prefix(1U);
        }
        while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
        {
            text.remove_suffix(1U);
        }
        return text;
    }

    // `application/json`, alone or with the one parameter `charset=utf-8`, in any ASCII case (RFC 9110 section 8.3.1:
    // type, subtype and parameter names are case-insensitive). Anything else is refused rather than guessed at: the
    // body is read as JSON and nothing else.
    [[nodiscard]] auto content_type_is_json(std::string_view content_type) noexcept -> bool
    {
        auto const separator = content_type.find(';');
        if (!equals_ignoring_ascii_case(trim_whitespace(content_type.substr(0U, separator)), "application/json"))
        {
            return false;
        }
        if (separator == std::string_view::npos)
        {
            return true;
        }
        auto const parameter = trim_whitespace(content_type.substr(separator + 1U));
        return equals_ignoring_ascii_case(parameter, "charset=utf-8") ||
               equals_ignoring_ascii_case(parameter, "charset=\"utf-8\"");
    }

    [[nodiscard]] auto application_type_name(oauth::ApplicationType type) noexcept -> std::string_view
    {
        return type == oauth::ApplicationType::native ? "native" : "web";
    }

    auto log_oauth(std::string_view event, std::vector<observability::StructuredLogField> fields,
                   observability::LogEventSeverity severity) -> void
    {
        observability::log_diagnostic("oauth", event, std::move(fields), severity);
    }

    // The 201 body: the registered metadata, the client ID and when it was first issued (RFC 7591 section 3.2.1).
    [[nodiscard]] auto registration_response(oauth::ClientMetadata const& metadata, std::string const& client_id,
                                             std::uint64_t created_at_ms) -> LocalHttpResponse
    {
        auto const registered = metadata.to_json();
        auto const* members = std::get_if<canonicaljson::Object>(&registered.storage());
        if (members == nullptr)
        {
            return server_error("The registered client metadata could not be written.");
        }
        auto object = *members;
        object.push_back(canonicaljson::make_member("client_id", canonicaljson::Value{client_id}));
        auto const issued_at_seconds = created_at_ms / 1000U;
        object.push_back(canonicaljson::make_member(
            "client_id_issued_at",
            canonicaljson::Value{static_cast<std::int64_t>(
                issued_at_seconds > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
                    ? static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())
                    : issued_at_seconds)}));
        return oauth_json_response(201U, canonicaljson::Value{std::move(object)});
    }

    // Makes room for one more client at the cap by deleting idle clients, least recently used first (ADR-0780). True
    // when there is room afterwards. Never deletes a client with a session (delete_oauth_clients refuses one, and
    // oauth_clients_without_sessions never offers one) nor one a pending authorisation names.
    [[nodiscard]] auto make_room_for_a_client(ClientServerRuntime& runtime) -> bool
    {
        auto& store = runtime.homeserver.database.persistent_store;
        auto const held = database::oauth_client_count(store);
        auto const limit = runtime.limits.max_oauth_clients;
        if (held < limit)
        {
            return true;
        }
        auto const needed = held - limit + 1U;
        if (needed > max_oauth_client_evictions_per_registration)
        {
            return false;
        }
        auto const& homeserver = runtime.homeserver;
        auto const pending = [&homeserver](std::string_view client_id) {
            return oauth_client_has_pending_authorisation(homeserver, client_id);
        };
        auto const idle =
            database::oauth_clients_without_sessions(store, needed, std::numeric_limits<std::uint64_t>::max(), pending);
        if (idle.size() < needed || !database::delete_oauth_clients(store, idle))
        {
            return false;
        }
        log_oauth("oauth.client.evicted",
                  {
                      {"clients", std::to_string(idle.size()), false},
                      {"limit",   std::to_string(limit),       false}
        },
                  observability::LogEventSeverity::info);
        return true;
    }

} // namespace

auto oauth_client_id_of(HomeserverRuntime const& runtime, oauth::ClientMetadata const& metadata)
    -> std::optional<std::string>
{
    auto canonical = metadata.canonical_bytes();
    if (std::holds_alternative<core::Error>(canonical))
    {
        return std::nullopt;
    }
    auto const keys = crypto::cached_token_hmac_keys(runtime.config.security().secrets.master_key_file);
    if (keys == nullptr || !keys->oauth_client_id.has_value())
    {
        return std::nullopt;
    }
    return crypto::oauth_client_id(std::get<std::string>(canonical), *keys->oauth_client_id);
}

auto find_registered_oauth_client(HomeserverRuntime const& runtime, std::string_view client_id)
    -> std::optional<oauth::ClientMetadata>
{
    if (client_id.empty() || client_id.size() > database::max_oauth_client_id_bytes)
    {
        return std::nullopt;
    }
    auto const* row = database::find_oauth_client(runtime.database.persistent_store, client_id);
    if (row == nullptr)
    {
        return std::nullopt;
    }
    auto const parsed = canonicaljson::parse_json(row->metadata_json);
    if (parsed.error == canonicaljson::ParseError::none)
    {
        auto validated = oauth::ClientMetadata::validate(parsed.value);
        if (auto* metadata = std::get_if<oauth::ClientMetadata>(&validated); metadata != nullptr)
        {
            return std::move(*metadata);
        }
    }
    // A row this server wrote that its own rules now refuse (a rule tightened since): the client is unknown until it
    // registers again. Its metadata is attacker-chosen text, so it is not logged.
    log_oauth("oauth.client.stored_metadata_refused",
              {
                  {"client_id", std::string{client_id}, false}
    },
              observability::LogEventSeverity::warning);
    return std::nullopt;
}

auto oauth_client_metadata_too_large() -> LocalHttpResponse
{
    return invalid_metadata("The client metadata is larger than this server accepts.");
}

auto register_oauth_client(ClientServerRuntime& runtime, std::string_view content_type, std::string_view body)
    -> LocalHttpResponse
{
    if (body.size() > database::max_oauth_client_metadata_bytes)
    {
        return oauth_client_metadata_too_large();
    }
    if (!content_type_is_json(content_type))
    {
        return invalid_metadata("The client metadata must be sent as application/json.");
    }
    auto const parsed = canonicaljson::parse_json(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return invalid_metadata("The client metadata is not valid JSON.");
    }
    auto validated = oauth::ClientMetadata::validate(parsed.value);
    if (auto const* refused = std::get_if<oauth::OAuthRefusal>(&validated); refused != nullptr)
    {
        return oauth_error_response(400U, *refused);
    }
    auto const& metadata = std::get<oauth::ClientMetadata>(validated);
    auto canonical = metadata.canonical_bytes();
    if (std::holds_alternative<core::Error>(canonical))
    {
        return server_error("The client metadata could not be registered.");
    }
    auto& metadata_json = std::get<std::string>(canonical);
    if (metadata_json.size() > database::max_oauth_client_metadata_bytes)
    {
        // The defaults the server adds can take a body just under the cap over it.
        return oauth_client_metadata_too_large();
    }
    auto const client_id = oauth_client_id_of(runtime.homeserver, metadata);
    if (!client_id.has_value())
    {
        return server_error("The server cannot issue client IDs now.");
    }

    auto& store = runtime.homeserver.database.persistent_store;
    auto const now_ms = wall_clock_ms();
    auto const log_fields = std::vector<observability::StructuredLogField>{
        {"client_id",        *client_id,                                                      false},
        {"application_type", std::string{application_type_name(metadata.application_type())}, false},
        {"client_host",      metadata.client_uri().host_lower(),                              false},
    };
    if (auto const* held = database::find_oauth_client(store, *client_id); held != nullptr)
    {
        // The pointer is valid only until the next write; the touch is one.
        auto const created_at_ms = held->created_at_ms;
        if (!database::touch_oauth_client(store, *client_id, now_ms))
        {
            // The row is held and answered; only its last use is stale, which ages it towards eviction early.
            log_oauth("oauth.client.touch_failed", log_fields, observability::LogEventSeverity::warning);
        }
        log_oauth("oauth.client.registered_again", log_fields, observability::LogEventSeverity::debug);
        return registration_response(metadata, *client_id, created_at_ms);
    }

    if (!make_room_for_a_client(runtime))
    {
        log_oauth("oauth.client.cap_reached", log_fields, observability::LogEventSeverity::warning);
        return oauth_error_response(503U,
                                    refusal(oauth::error_temporarily_unavailable, core::ErrorCode::invalid_argument,
                                            "The server holds as many client registrations as it can."));
    }
    auto const stored = database::store_oauth_client(
        store, database::PersistentOAuthClient{*client_id, std::move(metadata_json), now_ms, now_ms});
    if (stored == database::OAuthClientStoreResult::refused)
    {
        log_oauth("oauth.client.store_failed", log_fields, observability::LogEventSeverity::warning);
        return server_error("The client could not be registered.");
    }
    log_oauth("oauth.client.registered", log_fields, observability::LogEventSeverity::info);
    return registration_response(metadata, *client_id, now_ms);
}

} // namespace merovingian::homeserver
