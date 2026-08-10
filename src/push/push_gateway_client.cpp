// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/push_gateway_client.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"

#include <algorithm>
#include <charconv>

namespace merovingian::push
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

    [[nodiscard]] auto make_bool_member(std::string_view key, bool value) -> canonicaljson::ObjectMember
    {
        return canonicaljson::make_member(std::string{key}, canonicaljson::Value{value});
    }

    [[nodiscard]] auto build_tweaks_object(PushGatewayDevice const& device) -> canonicaljson::Object
    {
        auto tweaks = canonicaljson::Object{};
        if (device.tweak_sound.has_value())
        {
            tweaks.push_back(make_str_member("sound", *device.tweak_sound));
        }
        if (device.tweak_highlight)
        {
            tweaks.push_back(make_bool_member("highlight", true));
        }
        return tweaks;
    }

    [[nodiscard]] auto build_device_object(PushGatewayDevice const& device) -> canonicaljson::Object
    {
        auto data = canonicaljson::Object{};
        if (device.data_format.has_value())
        {
            data.push_back(make_str_member("format", *device.data_format));
        }

        auto object = canonicaljson::Object{};
        object.push_back(make_str_member("app_id", device.app_id));
        object.push_back(canonicaljson::make_member("data", canonicaljson::Value{std::move(data)}));
        object.push_back(make_str_member("pushkey", device.pushkey));
        if (device.pushkey_ts != 0U)
        {
            object.push_back(make_int_member("pushkey_ts", static_cast<std::int64_t>(device.pushkey_ts)));
        }
        object.push_back(canonicaljson::make_member("tweaks", canonicaljson::Value{build_tweaks_object(device)}));
        return object;
    }

    [[nodiscard]] auto build_counts_object(PushGatewayCounts const& counts) -> canonicaljson::Object
    {
        // "Counts whose value is zero should be omitted."
        auto object = canonicaljson::Object{};
        if (counts.unread != 0U)
        {
            object.push_back(make_int_member("unread", static_cast<std::int64_t>(counts.unread)));
        }
        if (counts.missed_calls != 0U)
        {
            object.push_back(make_int_member("missed_calls", static_cast<std::int64_t>(counts.missed_calls)));
        }
        return object;
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        auto const it = std::ranges::find_if(object, [key](canonicaljson::ObjectMember const& member) {
            return member.key == key;
        });
        return it == object.end() ? nullptr : it->value.get();
    }

    // Minimal HTTPS URL parse: scheme, host, port (default 443), and the
    // path (including query/fragment) used verbatim as the request target.
    // Not a general-purpose URI parser — deliberately conservative, matching
    // identity::parse_identity_server_url's approach for the same reason
    // (SSRF-relevant input parsed by hand rather than pulling in a full URI
    // library).
    struct PushGatewayUrl final
    {
        std::string host{};
        std::uint16_t port{443U};
        std::string path{};
    };

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto parse_push_gateway_url(std::string_view url) -> std::optional<PushGatewayUrl>
    {
        constexpr auto scheme = std::string_view{"https://"};
        if (!starts_with(url, scheme))
        {
            return std::nullopt;
        }
        auto const authority_start = scheme.size();
        auto const slash = url.find('/', authority_start);
        if (slash == std::string_view::npos)
        {
            // Spec requires a path of exactly /_matrix/push/v1/notify.
            return std::nullopt;
        }
        auto const authority = url.substr(authority_start, slash - authority_start);
        if (authority.empty())
        {
            return std::nullopt;
        }

        auto out = PushGatewayUrl{};
        out.port = 443U;
        auto const colon = authority.rfind(':');
        if (colon != std::string_view::npos)
        {
            auto const port_str = authority.substr(colon + 1U);
            auto parsed_port = std::uint16_t{0U};
            auto const parse_result = std::from_chars(port_str.data(), port_str.data() + port_str.size(), parsed_port);
            if (parse_result.ec == std::errc{} && parse_result.ptr == port_str.data() + port_str.size() &&
                parsed_port != 0U)
            {
                out.host = std::string{authority.substr(0U, colon)};
                out.port = parsed_port;
            }
            else
            {
                out.host = std::string{authority};
            }
        }
        else
        {
            out.host = std::string{authority};
        }
        if (out.host.empty())
        {
            return std::nullopt;
        }

        auto const query_start = url.find('?', slash);
        auto const fragment_start = url.find('#', slash);
        auto const path_end = std::min(query_start, fragment_start);
        auto const path = url.substr(slash, path_end - slash);
        // Spec: "MUST be an HTTPS URL with a path of /_matrix/push/v1/notify".
        if (path != "/_matrix/push/v1/notify")
        {
            return std::nullopt;
        }
        out.path = std::string{url.substr(slash)};
        return out;
    }

} // namespace

auto build_notify_request_body(PushGatewayNotification const& notification) -> std::string
{
    auto devices = canonicaljson::Array{};
    for (auto const& device : notification.devices)
    {
        devices.emplace_back(build_device_object(device));
    }

    auto inner = canonicaljson::Object{};
    if (!notification.content_json.empty())
    {
        auto const parsed_content = canonicaljson::parse_json(notification.content_json);
        if (parsed_content.error == canonicaljson::ParseError::none)
        {
            inner.push_back(canonicaljson::make_member("content", canonicaljson::Value{parsed_content.value}));
        }
    }
    inner.push_back(
        canonicaljson::make_member("counts", canonicaljson::Value{build_counts_object(notification.counts)}));
    inner.push_back(canonicaljson::make_member("devices", canonicaljson::Value{std::move(devices)}));
    if (!notification.event_id.empty())
    {
        inner.push_back(make_str_member("event_id", notification.event_id));
    }
    inner.push_back(make_str_member("prio", notification.prio));
    if (!notification.room_alias.empty())
    {
        inner.push_back(make_str_member("room_alias", notification.room_alias));
    }
    if (!notification.room_id.empty())
    {
        inner.push_back(make_str_member("room_id", notification.room_id));
    }
    if (!notification.room_name.empty())
    {
        inner.push_back(make_str_member("room_name", notification.room_name));
    }
    if (!notification.sender.empty())
    {
        inner.push_back(make_str_member("sender", notification.sender));
    }
    if (!notification.sender_display_name.empty())
    {
        inner.push_back(make_str_member("sender_display_name", notification.sender_display_name));
    }
    if (!notification.type.empty())
    {
        inner.push_back(make_str_member("type", notification.type));
    }
    if (notification.user_is_target)
    {
        inner.push_back(make_bool_member("user_is_target", true));
    }

    auto root = canonicaljson::Object{};
    root.push_back(canonicaljson::make_member("notification", canonicaljson::Value{std::move(inner)}));
    return canonicaljson::serialize_canonical(canonicaljson::Value{std::move(root)}).output;
}

auto parse_notify_response(std::string_view body) -> std::optional<PushGatewayRejection>
{
    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return std::nullopt;
    }
    auto const* rejected_value = object_member(*root, "rejected");
    if (rejected_value == nullptr)
    {
        return std::nullopt;
    }
    auto const* rejected_array = std::get_if<canonicaljson::Array>(&rejected_value->storage());
    if (rejected_array == nullptr)
    {
        return std::nullopt;
    }

    auto result = PushGatewayRejection{};
    for (auto const& entry : *rejected_array)
    {
        if (auto const* pushkey = std::get_if<std::string>(&entry.storage()); pushkey != nullptr)
        {
            result.rejected_pushkeys.push_back(*pushkey);
        }
    }
    return result;
}

PushGatewayClient::PushGatewayClient(
    http::OutboundClient& outbound, federation::CachedServerDiscovery& discovery, config::PushConfig const& config,
    std::map<std::string, TestForcedPushGatewayResolution> const* forced_resolution) noexcept
    : outbound_{outbound}
    , discovery_{discovery}
    , config_{config}
    , test_forced_resolution_{forced_resolution}
{
}

auto PushGatewayClient::notify(std::string_view gateway_url, PushGatewayNotification const& notification)
    -> PushGatewayResult
{
    // Fail closed while push delivery is disabled: no DNS, no connection, no
    // bytes leave this process. This makes the config gate load-bearing even
    // if a future caller forgets to check config.enabled itself.
    if (!config_.enabled)
    {
        return {false, true, 0U, {}, http::OutboundError::none, "push delivery disabled by config"};
    }

    auto const parsed = parse_push_gateway_url(gateway_url);
    if (!parsed.has_value())
    {
        return {false, false, 0U, {}, http::OutboundError::invalid_url, "invalid push gateway URL"};
    }

    auto request = http::OutboundRequest{};
    // Test-only seam: a forced entry keyed by the gateway host pins loopback
    // addresses and an in-memory CA bundle instead of going through SSRF-safe
    // discovery. Always nullptr/empty in production — see
    // TestForcedPushGatewayResolution's doc comment.
    auto const* forced_entry = [&]() -> TestForcedPushGatewayResolution const* {
        if (test_forced_resolution_ == nullptr)
        {
            return nullptr;
        }
        auto const found = test_forced_resolution_->find(parsed->host);
        return found == test_forced_resolution_->end() ? nullptr : &found->second;
    }();
    if (forced_entry != nullptr)
    {
        request.pinned_addresses = forced_entry->pinned_addresses;
        request.trusted_ca_pem = forced_entry->trusted_ca_pem;
    }
    else
    {
        // SSRF-safe resolution: never resolve DNS directly and never accept a
        // client-supplied address. The gateway URL is attacker-influenced (any
        // client can register a pusher pointing anywhere), so this path is the
        // same discovery boundary the identity-server and federation clients use.
        auto const resolved = discovery_.upstream().lookup_addresses(parsed->host, parsed->port);
        if (!resolved.ok || resolved.addresses.empty())
        {
            return {false,
                    false,
                    0U,
                    {},
                    http::OutboundError::unresolved_host,
                    "SSRF-safe resolution failed for push gateway host: " + resolved.reason};
        }
        request.pinned_addresses = resolved.addresses;
    }

    request.method = "POST";
    request.url = std::string{gateway_url};
    request.body = build_notify_request_body(notification);
    request.connect_timeout_seconds = config_.connect_timeout_seconds;
    request.total_timeout_seconds = config_.total_timeout_seconds;
    request.headers.push_back(http::OutboundHeader{"Content-Type", "application/json"});

    auto const result = outbound_.perform(request);
    if (!result.ok)
    {
        return {false, false, 0U, {}, result.error, result.error_detail};
    }

    auto push_result = PushGatewayResult{};
    push_result.ok = true;
    push_result.status = result.response.status;
    if (result.response.status == 200U)
    {
        if (auto const rejection = parse_notify_response(result.response.body); rejection.has_value())
        {
            push_result.rejected_pushkeys = rejection->rejected_pushkeys;
        }
    }
    return push_result;
}

} // namespace merovingian::push
