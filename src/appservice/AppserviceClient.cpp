// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/appservice/AppserviceClient.hpp"

#include "merovingian/appservice/AppserviceCallResult.hpp"
#include "merovingian/appservice/AppservicePingResult.hpp"
#include "merovingian/appservice/AppserviceQueryResult.hpp"
#include "merovingian/appservice/AppserviceThirdPartyLocationsResult.hpp"
#include "merovingian/appservice/AppserviceThirdPartyProtocolResult.hpp"
#include "merovingian/appservice/AppserviceThirdPartyUsersResult.hpp"
#include "merovingian/appservice/AppserviceTransaction.hpp"
#include "merovingian/appservice/AppserviceTransactionEvent.hpp"
#include "merovingian/appservice/ThirdPartyFieldType.hpp"
#include "merovingian/appservice/ThirdPartyLocation.hpp"
#include "merovingian/appservice/ThirdPartyProtocol.hpp"
#include "merovingian/appservice/ThirdPartyProtocolInstance.hpp"
#include "merovingian/appservice/ThirdPartyUser.hpp"
#include "merovingian/appservice/CleartextPolicy.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/core/QueryParams.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::appservice
{
namespace
{

    [[nodiscard]] auto make_str_member(std::string_view key, std::string_view value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{std::string{value}});
    }

    [[nodiscard]] auto make_int_member(std::string_view key, std::int64_t value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{value});
    }

    [[nodiscard]] auto build_event_object(AppserviceTransactionEvent const& event) -> canonicaljson::Object
    {
        auto object = canonicaljson::Object{};
        if (!event.content_json.empty())
        {
            auto const parsed_content = canonicaljson::parse_json(event.content_json);
            if (parsed_content.error == canonicaljson::ParseError::none)
            {
                object.push_back(canonicaljson::make_member("content", canonicaljson::Value{parsed_content.value}));
            }
            else
            {
                object.push_back(canonicaljson::make_member("content", canonicaljson::Value{canonicaljson::Object{}}));
            }
        }
        else
        {
            object.push_back(canonicaljson::make_member("content", canonicaljson::Value{canonicaljson::Object{}}));
        }
        object.push_back(make_str_member("event_id", event.event_id));
        object.push_back(make_int_member("origin_server_ts", static_cast<std::int64_t>(event.origin_server_ts)));
        object.push_back(make_str_member("room_id", event.room_id));
        object.push_back(make_str_member("sender", event.sender));
        if (event.state_key.has_value())
        {
            object.push_back(make_str_member("state_key", *event.state_key));
        }
        object.push_back(make_str_member("type", event.type));
        return object;
    }

    [[nodiscard]] auto hs_token_string(AppserviceRegistration const& registration) -> std::string
    {
        auto const bytes = registration.hs_token.bytes();
        return {reinterpret_cast<char const*>(bytes.data()), bytes.size()};
    }

    [[nodiscard]] auto call_appservice(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery,
                                       std::vector<std::string> const& allow_cleartext_hosts,
                                       AppserviceRegistration const& registration, std::string_view method,
                                       std::string_view path_suffix, std::string body,
                                       std::uint32_t connect_timeout_seconds, std::uint32_t total_timeout_seconds,
                                       std::size_t response_max_size_bytes, AppserviceClient::Perform const& perform)
        -> std::pair<bool, http::OutboundResult>
    {
        if (!registration.url.has_value())
        {
            return {false, http::OutboundResult{}};
        }
        // ADR-0515: the same rule load_registrations applied, repeated here so a registration that reached
        // the client any other way still cannot send the hs_token in cleartext to an unlisted host. A
        // refusal makes no lookup and no connection.
        auto const problem = appservice_url_problem(*registration.url, allow_cleartext_hosts);
        auto const parsed = problem.has_value() ? std::nullopt : http::parse_outbound_url(*registration.url, true);
        if (!parsed.has_value())
        {
            auto failed = http::OutboundResult{};
            failed.ok = false;
            failed.error = http::OutboundError::invalid_url;
            failed.error_detail = "invalid appservice registration url";
            return {true, failed};
        }

        // Rebuilt from the parsed parts: an IPv6 literal is re-bracketed, the port is always explicit, and
        // one trailing '/' of the registration's own path is dropped so the suffix never yields "//".
        auto registration_path = std::string_view{parsed->path};
        if (!registration_path.empty() && registration_path.back() == '/')
        {
            registration_path.remove_suffix(1U);
        }
        auto request = http::OutboundRequest{};
        request.method = std::string{method};
        request.url = parsed->scheme + "://" + (parsed->ipv6_literal ? "[" + parsed->host + "]" : parsed->host) + ":" +
                      std::to_string(parsed->port) + std::string{registration_path} + std::string{path_suffix};
        request.body = std::move(body);
        request.headers.push_back(http::OutboundHeader{"Content-Type", "application/json"});
        // Spec (Matrix v1.19, "Authorisation", changed in v1.4): "Homeservers
        // MUST include an Authorization header, containing the hs_token".
        // The legacy `access_token` query-string form is deliberately not
        // sent alongside it — putting a secret in a URL risks it landing in
        // proxy/access logs, and every appservice this homeserver can be
        // configured against understands the modern header form.
        request.headers.push_back(http::OutboundHeader{"Authorization", "Bearer " + hs_token_string(registration)});
        // See AppserviceClient's doc comment: an appservice URL is
        // operator-configured, not attacker-influenced, so host resolution
        // below intentionally bypasses the private/loopback-address
        // rejection that applies to attacker-influenced destinations.
        // Cleartext http is enabled for the transport only because the
        // check above already limited it to a loopback IP literal or a
        // host the operator listed (ADR-0515).
        request.allow_cleartext_http = true;
        request.connect_timeout_seconds = connect_timeout_seconds;
        request.total_timeout_seconds = total_timeout_seconds;
        request.max_response_body_bytes = response_max_size_bytes;

        auto const resolved = discovery.upstream().lookup_addresses(parsed->host, parsed->port);
        if (!resolved.ok || resolved.addresses.empty())
        {
            auto failed = http::OutboundResult{};
            failed.ok = false;
            failed.error = http::OutboundError::unresolved_host;
            failed.error_detail = "failed to resolve appservice host: " + resolved.reason;
            return {true, failed};
        }
        request.pinned_addresses = resolved.addresses;

        return {true, perform ? perform(request) : outbound.perform(request)};
    }

    // ── Third-party lookups: bounded, defensive parsing of untrusted
    // appservice responses ──────────────────────────────────────────────
    //
    // An appservice/bridge is not a trusted peer (src/appservice/AGENTS.md):
    // every field below is type-checked and length/count-bounded before it
    // is stored, and a malformed entry is dropped rather than propagated —
    // one bad entry in an array must not sink the whole response when other
    // entries are well-formed.
    constexpr std::size_t kMaxThirdPartyArrayEntries = 200U;
    constexpr std::size_t kMaxThirdPartyObjectMembers = 64U;
    constexpr std::size_t kMaxThirdPartyStringLength = 2048U;
    constexpr std::size_t kMaxThirdPartyInstances = 64U;
    constexpr std::size_t kMaxThirdPartyFieldTypes = 64U;
    constexpr std::size_t kMaxThirdPartyFieldNames = 64U;

    [[nodiscard]] auto bounded_string(std::string_view value) -> std::string
    {
        return std::string{value.substr(0U, std::min(value.size(), kMaxThirdPartyStringLength))};
    }

    [[nodiscard]] auto thirdparty_object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto thirdparty_string_field(canonicaljson::Object const& object, std::string_view key) -> std::string
    {
        auto const* value = thirdparty_object_member(object, key);
        if (value == nullptr)
        {
            return {};
        }
        auto const* str = std::get_if<std::string>(&value->storage());
        return str == nullptr ? std::string{} : bounded_string(*str);
    }

    // Bounds a `fields`-shaped object (Location.fields, User.fields,
    // ProtocolInstance.fields): every example of this shape in the spec
    // carries plain string values, so a non-string member is dropped rather
    // than trusted through as some other JSON type the client did not ask
    // for.
    [[nodiscard]] auto bounded_fields_object(canonicaljson::Object const& source) -> canonicaljson::Object
    {
        auto out = canonicaljson::Object{};
        for (auto const& member : source)
        {
            if (out.size() >= kMaxThirdPartyObjectMembers)
            {
                break;
            }
            if (member.value == nullptr)
            {
                continue;
            }
            auto const* str_value = std::get_if<std::string>(&member.value->storage());
            if (str_value == nullptr)
            {
                continue;
            }
            out.push_back(canonicaljson::make_member(bounded_string(member.key),
                                                     canonicaljson::Value{bounded_string(*str_value)}));
        }
        return out;
    }

    [[nodiscard]] auto thirdparty_fields_member(canonicaljson::Object const& object) -> canonicaljson::Object
    {
        auto const* value = thirdparty_object_member(object, "fields");
        if (value == nullptr)
        {
            return {};
        }
        auto const* fields_object = std::get_if<canonicaljson::Object>(&value->storage());
        return fields_object == nullptr ? canonicaljson::Object{} : bounded_fields_object(*fields_object);
    }

    // Spec: Location requires `alias`, `fields`, `protocol`. An entry
    // missing either required string is dropped rather than defaulted to
    // empty, so a malformed entry never masquerades as a real (if blank)
    // result.
    [[nodiscard]] auto parse_thirdparty_location_entry(canonicaljson::Object const& object)
        -> std::optional<ThirdPartyLocation>
    {
        auto const* alias_value = thirdparty_object_member(object, "alias");
        auto const* protocol_value = thirdparty_object_member(object, "protocol");
        auto const* alias_str = alias_value == nullptr ? nullptr : std::get_if<std::string>(&alias_value->storage());
        auto const* protocol_str =
            protocol_value == nullptr ? nullptr : std::get_if<std::string>(&protocol_value->storage());
        if (alias_str == nullptr || protocol_str == nullptr)
        {
            return std::nullopt;
        }
        auto result = ThirdPartyLocation{};
        result.alias = bounded_string(*alias_str);
        result.protocol = bounded_string(*protocol_str);
        result.fields = thirdparty_fields_member(object);
        return result;
    }

    // Spec: User requires `fields`, `protocol`, `userid`.
    [[nodiscard]] auto parse_thirdparty_user_entry(canonicaljson::Object const& object) -> std::optional<ThirdPartyUser>
    {
        auto const* userid_value = thirdparty_object_member(object, "userid");
        auto const* protocol_value = thirdparty_object_member(object, "protocol");
        auto const* userid_str = userid_value == nullptr ? nullptr : std::get_if<std::string>(&userid_value->storage());
        auto const* protocol_str =
            protocol_value == nullptr ? nullptr : std::get_if<std::string>(&protocol_value->storage());
        if (userid_str == nullptr || protocol_str == nullptr)
        {
            return std::nullopt;
        }
        auto result = ThirdPartyUser{};
        result.userid = bounded_string(*userid_str);
        result.protocol = bounded_string(*protocol_str);
        result.fields = thirdparty_fields_member(object);
        return result;
    }

    [[nodiscard]] auto parse_thirdparty_location_array(canonicaljson::Value const& root)
        -> std::vector<ThirdPartyLocation>
    {
        auto out = std::vector<ThirdPartyLocation>{};
        auto const* array = std::get_if<canonicaljson::Array>(&root.storage());
        if (array == nullptr)
        {
            return out;
        }
        for (auto const& entry : *array)
        {
            if (out.size() >= kMaxThirdPartyArrayEntries)
            {
                break;
            }
            auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
            if (object == nullptr)
            {
                continue;
            }
            if (auto parsed = parse_thirdparty_location_entry(*object); parsed.has_value())
            {
                out.push_back(std::move(*parsed));
            }
        }
        return out;
    }

    [[nodiscard]] auto parse_thirdparty_user_array(canonicaljson::Value const& root) -> std::vector<ThirdPartyUser>
    {
        auto out = std::vector<ThirdPartyUser>{};
        auto const* array = std::get_if<canonicaljson::Array>(&root.storage());
        if (array == nullptr)
        {
            return out;
        }
        for (auto const& entry : *array)
        {
            if (out.size() >= kMaxThirdPartyArrayEntries)
            {
                break;
            }
            auto const* object = std::get_if<canonicaljson::Object>(&entry.storage());
            if (object == nullptr)
            {
                continue;
            }
            if (auto parsed = parse_thirdparty_user_entry(*object); parsed.has_value())
            {
                out.push_back(std::move(*parsed));
            }
        }
        return out;
    }

    // Spec: Protocol requires `field_types`, `icon`, `instances`,
    // `location_fields`, `user_fields`. `icon` is treated leniently (defaults
    // to empty rather than failing the whole parse) because it is purely
    // cosmetic (a content URI the client displays) and dropping it costs the
    // client nothing it cannot already tolerate — unlike the required fields
    // on Location/User above, which identify the result itself.
    [[nodiscard]] auto parse_thirdparty_protocol_object(canonicaljson::Value const& root)
        -> std::optional<ThirdPartyProtocol>
    {
        auto const* object = std::get_if<canonicaljson::Object>(&root.storage());
        if (object == nullptr)
        {
            return std::nullopt;
        }
        auto result = ThirdPartyProtocol{};
        result.icon = thirdparty_string_field(*object, "icon");

        if (auto const* field_types_value = thirdparty_object_member(*object, "field_types");
            field_types_value != nullptr)
        {
            if (auto const* field_types_object = std::get_if<canonicaljson::Object>(&field_types_value->storage());
                field_types_object != nullptr)
            {
                for (auto const& member : *field_types_object)
                {
                    if (result.field_types.size() >= kMaxThirdPartyFieldTypes)
                    {
                        break;
                    }
                    if (member.value == nullptr)
                    {
                        continue;
                    }
                    auto const* entry_object = std::get_if<canonicaljson::Object>(&member.value->storage());
                    if (entry_object == nullptr)
                    {
                        continue;
                    }
                    auto field_type = ThirdPartyFieldType{};
                    field_type.placeholder = thirdparty_string_field(*entry_object, "placeholder");
                    field_type.regexp = thirdparty_string_field(*entry_object, "regexp");
                    result.field_types.emplace_back(bounded_string(member.key), std::move(field_type));
                }
            }
        }

        auto const collect_field_names = [](canonicaljson::Object const& source_object,
                                            std::string_view key) -> std::vector<std::string> {
            auto names = std::vector<std::string>{};
            auto const* value = thirdparty_object_member(source_object, key);
            if (value == nullptr)
            {
                return names;
            }
            auto const* array = std::get_if<canonicaljson::Array>(&value->storage());
            if (array == nullptr)
            {
                return names;
            }
            for (auto const& entry : *array)
            {
                if (names.size() >= kMaxThirdPartyFieldNames)
                {
                    break;
                }
                if (auto const* str = std::get_if<std::string>(&entry.storage()); str != nullptr)
                {
                    names.push_back(bounded_string(*str));
                }
            }
            return names;
        };
        result.location_fields = collect_field_names(*object, "location_fields");
        result.user_fields = collect_field_names(*object, "user_fields");

        if (auto const* instances_value = thirdparty_object_member(*object, "instances"); instances_value != nullptr)
        {
            if (auto const* instances_array = std::get_if<canonicaljson::Array>(&instances_value->storage());
                instances_array != nullptr)
            {
                for (auto const& entry : *instances_array)
                {
                    if (result.instances.size() >= kMaxThirdPartyInstances)
                    {
                        break;
                    }
                    auto const* instance_object = std::get_if<canonicaljson::Object>(&entry.storage());
                    if (instance_object == nullptr)
                    {
                        continue;
                    }
                    auto instance = ThirdPartyProtocolInstance{};
                    instance.desc = thirdparty_string_field(*instance_object, "desc");
                    instance.icon = thirdparty_string_field(*instance_object, "icon");
                    instance.network_id = thirdparty_string_field(*instance_object, "network_id");
                    instance.fields = thirdparty_fields_member(*instance_object);
                    result.instances.push_back(std::move(instance));
                }
            }
        }
        return result;
    }

    // Builds the outbound query-string suffix from an ordered set of
    // protocol-defined search fields, e.g. `?channel=%23matrix&network=freenode`.
    // Empty when `fields` is empty (no trailing bare "?").
    [[nodiscard]] auto build_thirdparty_fields_query(std::vector<std::pair<std::string, std::string>> const& fields)
        -> std::string
    {
        if (fields.empty())
        {
            return {};
        }
        auto out = std::string{"?"};
        auto first = true;
        for (auto const& [key, value] : fields)
        {
            if (!first)
            {
                out.push_back('&');
            }
            first = false;
            out += core::percent_encode_path_component(key);
            out.push_back('=');
            out += core::percent_encode_path_component(value);
        }
        return out;
    }

} // namespace

auto parse_thirdparty_protocol_response(canonicaljson::Value const& parsed_body) -> std::optional<ThirdPartyProtocol>
{
    return parse_thirdparty_protocol_object(parsed_body);
}

auto parse_thirdparty_location_response(canonicaljson::Value const& parsed_body) -> std::vector<ThirdPartyLocation>
{
    return parse_thirdparty_location_array(parsed_body);
}

auto parse_thirdparty_user_response(canonicaljson::Value const& parsed_body) -> std::vector<ThirdPartyUser>
{
    return parse_thirdparty_user_array(parsed_body);
}

auto build_transaction_request_body(AppserviceTransaction const& transaction) -> std::string
{
    auto events = canonicaljson::Array{};
    for (auto const& event : transaction.events)
    {
        events.emplace_back(build_event_object(event));
    }
    auto root = canonicaljson::Object{};
    root.push_back(canonicaljson::make_member("events", canonicaljson::Value{std::move(events)}));
    // "ephemeral" is optional: it is sent only when there is something in it. An element that
    // does not parse is skipped rather than failing the events it travels with.
    auto ephemeral = canonicaljson::Array{};
    for (auto const& json : transaction.ephemeral_json)
    {
        auto parsed = canonicaljson::parse_json(json);
        if (parsed.error == canonicaljson::ParseError::none)
        {
            ephemeral.emplace_back(std::move(parsed.value));
        }
    }
    if (!ephemeral.empty())
    {
        root.push_back(canonicaljson::make_member("ephemeral", canonicaljson::Value{std::move(ephemeral)}));
    }
    return canonicaljson::serialize_canonical(canonicaljson::Value{std::move(root)}).output;
}

auto build_ping_request_body(std::optional<std::string_view> transaction_id) -> std::string
{
    auto root = canonicaljson::Object{};
    if (transaction_id.has_value())
    {
        root.push_back(make_str_member("transaction_id", *transaction_id));
    }
    return canonicaljson::serialize_canonical(canonicaljson::Value{std::move(root)}).output;
}

AppserviceClient::AppserviceClient(http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery,
                                   config::AppserviceConfig const& appservice_config, Perform perform)
    : outbound_{outbound}
    , discovery_{discovery}
    , connect_timeout_seconds_{appservice_config.connect_timeout_seconds}
    , total_timeout_seconds_{appservice_config.total_timeout_seconds}
    , allow_cleartext_hosts_{appservice_config.allow_cleartext_hosts}
    , perform_{std::move(perform)}
{
    auto const response_limit = config::parse_size_limit(appservice_config.response_max_size);
    if (response_limit.valid && response_limit.bytes <= std::numeric_limits<std::size_t>::max())
    {
        response_max_size_bytes_ = static_cast<std::size_t>(response_limit.bytes);
    }
}

auto AppserviceClient::send_transaction(AppserviceRegistration const& registration,
                                        AppserviceTransaction const& transaction) -> AppserviceCallResult
{
    auto const path = "/_matrix/app/v1/transactions/" + core::percent_encode_path_component(transaction.txn_id);
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "PUT", path,
                        build_transaction_request_body(transaction), connect_timeout_seconds_, total_timeout_seconds_,
                        response_max_size_bytes_, perform_);
    if (!attempted)
    {
        return {false, true, 0U, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, result.error, result.error_detail};
    }
    return {result.response.status == 200U, false, result.response.status, http::OutboundError::none, {}};
}

auto AppserviceClient::ping(AppserviceRegistration const& registration, std::optional<std::string_view> transaction_id)
    -> AppservicePingResult
{
    auto ping_result = AppservicePingResult{};
    if (!registration.url.has_value())
    {
        ping_result.failure = AppservicePingFailure::url_not_set;
        return ping_result;
    }
    auto const started = std::chrono::steady_clock::now();
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "POST", "/_matrix/app/v1/ping",
                        build_ping_request_body(transaction_id), connect_timeout_seconds_, total_timeout_seconds_,
                        response_max_size_bytes_, perform_);
    ping_result.duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
    if (!attempted)
    {
        ping_result.failure = AppservicePingFailure::url_not_set;
        return ping_result;
    }
    auto const answered = result.ok || result.error == http::OutboundError::redirect_rejected;
    if (!answered)
    {
        // A timeout is its own error ("504 M_CONNECTION_TIMEOUT"); every other way of not getting an
        // answer (no route, refused, TLS, an unusable URL, an oversize reply) is a failed connection.
        ping_result.failure = result.error == http::OutboundError::timeout ? AppservicePingFailure::connection_timeout
                                                                           : AppservicePingFailure::connection_failed;
        ping_result.error = result.error;
        ping_result.error_detail = result.error_detail;
        return ping_result;
    }
    // The spec's 200 is the only success; an appservice that redirects has answered with a status too.
    if (result.ok && result.response.status == 200U)
    {
        return ping_result;
    }
    ping_result.failure = AppservicePingFailure::bad_status;
    ping_result.status = result.response.status;
    ping_result.body = result.response.body.substr(0U, max_ping_body_bytes);
    return ping_result;
}

auto AppserviceClient::perform_query(AppserviceRegistration const& registration, std::string_view path)
    -> AppserviceQueryResult
{
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "GET", path, {},
                        connect_timeout_seconds_, total_timeout_seconds_, response_max_size_bytes_, perform_);
    if (!attempted)
    {
        return {false, true, 0U, false, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, false, result.error, result.error_detail};
    }
    // Spec: 200 = exists, 404 = does not exist. Anything else (401/403/5xx)
    // is neither — the caller must not read `exists` when `ok` is false.
    if (result.response.status == 200U)
    {
        return {true, false, 200U, true, http::OutboundError::none, {}};
    }
    if (result.response.status == 404U)
    {
        return {true, false, 404U, false, http::OutboundError::none, {}};
    }
    return {
        false, false, result.response.status, false, http::OutboundError::none, "unexpected appservice query status"};
}

auto AppserviceClient::query_user(AppserviceRegistration const& registration, std::string_view user_id)
    -> AppserviceQueryResult
{
    return perform_query(registration, "/_matrix/app/v1/users/" + core::percent_encode_path_component(user_id));
}

auto AppserviceClient::query_room_alias(AppserviceRegistration const& registration, std::string_view room_alias)
    -> AppserviceQueryResult
{
    return perform_query(registration, "/_matrix/app/v1/rooms/" + core::percent_encode_path_component(room_alias));
}

auto AppserviceClient::query_thirdparty_protocol(AppserviceRegistration const& registration, std::string_view protocol)
    -> AppserviceThirdPartyProtocolResult
{
    auto const path = "/_matrix/app/v1/thirdparty/protocol/" + core::percent_encode_path_component(protocol);
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "GET", path, {},
                        connect_timeout_seconds_, total_timeout_seconds_, response_max_size_bytes_, perform_);
    if (!attempted)
    {
        return {false, true, 0U, false, {}, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, false, {}, result.error, result.error_detail};
    }
    // Spec: 200 = found, 404 = "no protocol was found with the given path".
    if (result.response.status == 404U)
    {
        return {true, false, 404U, false, {}, http::OutboundError::none, {}};
    }
    if (result.response.status != 200U)
    {
        return {false,
                false,
                result.response.status,
                false,
                {},
                http::OutboundError::none,
                "unexpected appservice thirdparty status"};
    }
    auto const parsed = canonicaljson::parse_json(result.response.body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        // A 200 with an unparseable/malformed body is neither "found" nor
        // "not found" — it is a broken or hostile peer, so `ok` stays false
        // rather than degrading to a 404-shaped "not found" answer.
        return {false, false, 200U, false, {}, http::OutboundError::none, "malformed thirdparty protocol response"};
    }
    auto protocol_value = parse_thirdparty_protocol_object(parsed.value);
    if (!protocol_value.has_value())
    {
        return {false, false, 200U, false, {}, http::OutboundError::none, "malformed thirdparty protocol response"};
    }
    return {true, false, 200U, true, std::move(*protocol_value), http::OutboundError::none, {}};
}

auto AppserviceClient::query_thirdparty_location_by_alias(AppserviceRegistration const& registration,
                                                          std::string_view alias) -> AppserviceThirdPartyLocationsResult
{
    auto const path = "/_matrix/app/v1/thirdparty/location?alias=" + core::percent_encode_path_component(alias);
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "GET", path, {},
                        connect_timeout_seconds_, total_timeout_seconds_, response_max_size_bytes_, perform_);
    if (!attempted)
    {
        return {false, true, 0U, false, {}, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, false, {}, result.error, result.error_detail};
    }
    if (result.response.status == 404U)
    {
        return {true, false, 404U, false, {}, http::OutboundError::none, {}};
    }
    if (result.response.status != 200U)
    {
        return {false,
                false,
                result.response.status,
                false,
                {},
                http::OutboundError::none,
                "unexpected appservice thirdparty status"};
    }
    auto const parsed = canonicaljson::parse_json(result.response.body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {false, false, 200U, false, {}, http::OutboundError::none, "malformed thirdparty location response"};
    }
    return {true, false, 200U, true, parse_thirdparty_location_array(parsed.value), http::OutboundError::none, {}};
}

auto AppserviceClient::query_thirdparty_location_by_protocol(
    AppserviceRegistration const& registration, std::string_view protocol,
    std::vector<std::pair<std::string, std::string>> const& fields) -> AppserviceThirdPartyLocationsResult
{
    auto const path = "/_matrix/app/v1/thirdparty/location/" + core::percent_encode_path_component(protocol) +
                      build_thirdparty_fields_query(fields);
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "GET", path, {},
                        connect_timeout_seconds_, total_timeout_seconds_, response_max_size_bytes_, perform_);
    if (!attempted)
    {
        return {false, true, 0U, false, {}, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, false, {}, result.error, result.error_detail};
    }
    if (result.response.status == 404U)
    {
        return {true, false, 404U, false, {}, http::OutboundError::none, {}};
    }
    if (result.response.status != 200U)
    {
        return {false,
                false,
                result.response.status,
                false,
                {},
                http::OutboundError::none,
                "unexpected appservice thirdparty status"};
    }
    auto const parsed = canonicaljson::parse_json(result.response.body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {false, false, 200U, false, {}, http::OutboundError::none, "malformed thirdparty location response"};
    }
    return {true, false, 200U, true, parse_thirdparty_location_array(parsed.value), http::OutboundError::none, {}};
}

auto AppserviceClient::query_thirdparty_user_by_userid(AppserviceRegistration const& registration,
                                                       std::string_view user_id) -> AppserviceThirdPartyUsersResult
{
    auto const path = "/_matrix/app/v1/thirdparty/user?userid=" + core::percent_encode_path_component(user_id);
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "GET", path, {},
                        connect_timeout_seconds_, total_timeout_seconds_, response_max_size_bytes_, perform_);
    if (!attempted)
    {
        return {false, true, 0U, false, {}, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, false, {}, result.error, result.error_detail};
    }
    if (result.response.status == 404U)
    {
        return {true, false, 404U, false, {}, http::OutboundError::none, {}};
    }
    if (result.response.status != 200U)
    {
        return {false,
                false,
                result.response.status,
                false,
                {},
                http::OutboundError::none,
                "unexpected appservice thirdparty status"};
    }
    auto const parsed = canonicaljson::parse_json(result.response.body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {false, false, 200U, false, {}, http::OutboundError::none, "malformed thirdparty user response"};
    }
    return {true, false, 200U, true, parse_thirdparty_user_array(parsed.value), http::OutboundError::none, {}};
}

auto AppserviceClient::query_thirdparty_user_by_protocol(AppserviceRegistration const& registration,
                                                         std::string_view protocol,
                                                         std::vector<std::pair<std::string, std::string>> const& fields)
    -> AppserviceThirdPartyUsersResult
{
    auto const path = "/_matrix/app/v1/thirdparty/user/" + core::percent_encode_path_component(protocol) +
                      build_thirdparty_fields_query(fields);
    auto const [attempted, result] =
        call_appservice(outbound_, discovery_, allow_cleartext_hosts_, registration, "GET", path, {},
                        connect_timeout_seconds_, total_timeout_seconds_, response_max_size_bytes_, perform_);
    if (!attempted)
    {
        return {false, true, 0U, false, {}, http::OutboundError::none, "appservice has no url configured"};
    }
    if (!result.ok)
    {
        return {false, false, 0U, false, {}, result.error, result.error_detail};
    }
    if (result.response.status == 404U)
    {
        return {true, false, 404U, false, {}, http::OutboundError::none, {}};
    }
    if (result.response.status != 200U)
    {
        return {false,
                false,
                result.response.status,
                false,
                {},
                http::OutboundError::none,
                "unexpected appservice thirdparty status"};
    }
    auto const parsed = canonicaljson::parse_json(result.response.body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {false, false, 200U, false, {}, http::OutboundError::none, "malformed thirdparty user response"};
    }
    return {true, false, 200U, true, parse_thirdparty_user_array(parsed.value), http::OutboundError::none, {}};
}

} // namespace merovingian::appservice
