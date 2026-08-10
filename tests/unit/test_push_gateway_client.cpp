// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            PUSH GATEWAY API CLIENT — PURE HELPER UNIT TESTS            |
// |                                                                         |
// |  Spec: Matrix Push Gateway API v1.19, POST /_matrix/push/v1/notify     |
// |  URL:  ../../docs/matrix-v1.19-spec/push-gateway-api.md                 |
// |                                                                         |
// |  Covers the network-free helpers (request-body builder, response       |
// |  parser) plus the config-gate fail-closed path, which never reaches    |
// |  the transport. Live delivery against a mock gateway belongs in        |
// |  conformance/integration, matching the identity-client precedent.      |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/push/push_gateway_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <variant>

namespace
{

[[nodiscard]] auto object_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> merovingian::canonicaljson::Value const*
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

[[nodiscard]] auto parse_object(std::string_view json) -> merovingian::canonicaljson::Object
{
    auto const parsed = merovingian::canonicaljson::parse_json(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

// A minimal ServerDiscoveryNetwork test double that counts lookups. Used
// only to prove the config-disabled path in PushGatewayClient::notify()
// never reaches discovery, matching the pattern in test_remote_key_cache.cpp.
struct CountingDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
    std::uint64_t lookup_calls{0U};

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        ++lookup_calls;
        return {true, {"203.0.113.1"}, {}};
    }
};

} // namespace

SCENARIO("build_notify_request_body produces the Push Gateway API's notification shape", "[push][push-gateway]")
{
    GIVEN("a notification with one device and non-zero counts")
    {
        auto notification = merovingian::push::PushGatewayNotification{};
        notification.event_id = "$event:example.org";
        notification.room_id = "!room:example.org";
        notification.room_name = "Mission Control";
        notification.type = "m.room.message";
        notification.sender = "@alice:example.org";
        notification.sender_display_name = "Alice";
        notification.prio = "high";
        notification.counts = {2U, 1U};

        auto device = merovingian::push::PushGatewayDevice{};
        device.app_id = "org.matrix.console.ios";
        device.pushkey = "abc123";
        device.pushkey_ts = 12345678U;
        device.data_format = "event_id_only";
        device.tweak_sound = "bing";
        device.tweak_highlight = true;
        notification.devices.push_back(device);

        WHEN("the request body is built")
        {
            auto const body = merovingian::push::build_notify_request_body(notification);
            auto const root = parse_object(body);
            auto const* inner_value = object_member(root, "notification");

            THEN("it nests every field under a top-level notification object")
            {
                REQUIRE(inner_value != nullptr);
                auto const* inner = std::get_if<merovingian::canonicaljson::Object>(&inner_value->storage());
                REQUIRE(inner != nullptr);

                auto const* event_id = object_member(*inner, "event_id");
                REQUIRE(event_id != nullptr);
                REQUIRE(std::get<std::string>(event_id->storage()) == "$event:example.org");

                auto const* counts_value = object_member(*inner, "counts");
                REQUIRE(counts_value != nullptr);
                auto const* counts = std::get_if<merovingian::canonicaljson::Object>(&counts_value->storage());
                REQUIRE(counts != nullptr);
                auto const* unread = object_member(*counts, "unread");
                auto const* missed_calls = object_member(*counts, "missed_calls");
                REQUIRE(unread != nullptr);
                REQUIRE(missed_calls != nullptr);
                REQUIRE(std::get<std::int64_t>(unread->storage()) == 2);
                REQUIRE(std::get<std::int64_t>(missed_calls->storage()) == 1);

                auto const* devices_value = object_member(*inner, "devices");
                REQUIRE(devices_value != nullptr);
                auto const* devices = std::get_if<merovingian::canonicaljson::Array>(&devices_value->storage());
                REQUIRE(devices != nullptr);
                REQUIRE(devices->size() == 1U);
                auto const* device_object = std::get_if<merovingian::canonicaljson::Object>(&(*devices)[0].storage());
                REQUIRE(device_object != nullptr);

                auto const* app_id = object_member(*device_object, "app_id");
                auto const* pushkey = object_member(*device_object, "pushkey");
                REQUIRE(app_id != nullptr);
                REQUIRE(pushkey != nullptr);
                REQUIRE(std::get<std::string>(app_id->storage()) == "org.matrix.console.ios");
                REQUIRE(std::get<std::string>(pushkey->storage()) == "abc123");

                auto const* data_value = object_member(*device_object, "data");
                REQUIRE(data_value != nullptr);
                auto const* data = std::get_if<merovingian::canonicaljson::Object>(&data_value->storage());
                REQUIRE(data != nullptr);
                auto const* format = object_member(*data, "format");
                REQUIRE(format != nullptr);
                REQUIRE(std::get<std::string>(format->storage()) == "event_id_only");

                auto const* tweaks_value = object_member(*device_object, "tweaks");
                REQUIRE(tweaks_value != nullptr);
                auto const* tweaks = std::get_if<merovingian::canonicaljson::Object>(&tweaks_value->storage());
                REQUIRE(tweaks != nullptr);
                auto const* sound = object_member(*tweaks, "sound");
                auto const* highlight = object_member(*tweaks, "highlight");
                REQUIRE(sound != nullptr);
                REQUIRE(highlight != nullptr);
                REQUIRE(std::get<std::string>(sound->storage()) == "bing");
                REQUIRE(std::get<bool>(highlight->storage()));
            }
        }
    }

    GIVEN("a notification with zero counts and a device with no tweaks")
    {
        auto notification = merovingian::push::PushGatewayNotification{};
        auto device = merovingian::push::PushGatewayDevice{};
        device.app_id = "org.matrix.console.ios";
        device.pushkey = "abc123";
        notification.devices.push_back(device);

        WHEN("the request body is built")
        {
            auto const body = merovingian::push::build_notify_request_body(notification);
            auto const root = parse_object(body);
            auto const* inner_value = object_member(root, "notification");
            auto const* inner = std::get_if<merovingian::canonicaljson::Object>(&inner_value->storage());
            REQUIRE(inner != nullptr);

            THEN("zero-valued counts are omitted, per spec (\"Counts whose value is zero should be omitted\")")
            {
                auto const* counts_value = object_member(*inner, "counts");
                REQUIRE(counts_value != nullptr);
                auto const* counts = std::get_if<merovingian::canonicaljson::Object>(&counts_value->storage());
                REQUIRE(counts != nullptr);
                REQUIRE(counts->empty());
            }

            THEN("a device with no tweaks still carries an empty tweaks object")
            {
                auto const* devices_value = object_member(*inner, "devices");
                auto const* devices = std::get_if<merovingian::canonicaljson::Array>(&devices_value->storage());
                REQUIRE(devices != nullptr);
                auto const* device_object = std::get_if<merovingian::canonicaljson::Object>(&(*devices)[0].storage());
                REQUIRE(device_object != nullptr);
                auto const* tweaks_value = object_member(*device_object, "tweaks");
                REQUIRE(tweaks_value != nullptr);
                auto const* tweaks = std::get_if<merovingian::canonicaljson::Object>(&tweaks_value->storage());
                REQUIRE(tweaks != nullptr);
                REQUIRE(tweaks->empty());
            }
        }
    }
}

SCENARIO("parse_notify_response reads the rejected pushkey list and fails closed on a malformed body",
         "[push][push-gateway]")
{
    GIVEN("a well-formed 200 response with rejected pushkeys")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::push::parse_notify_response(R"({"rejected":["deadbeef","cafef00d"]})");

            THEN("both rejected pushkeys are returned in order")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->rejected_pushkeys.size() == 2U);
                REQUIRE(parsed->rejected_pushkeys[0] == "deadbeef");
                REQUIRE(parsed->rejected_pushkeys[1] == "cafef00d");
            }
        }
    }

    GIVEN("a well-formed 200 response with an empty rejected list")
    {
        WHEN("parsed")
        {
            auto const parsed = merovingian::push::parse_notify_response(R"({"rejected":[]})");

            THEN("the rejection list is present but empty")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->rejected_pushkeys.empty());
            }
        }
    }

    GIVEN("a body missing the required rejected field, and one that is not valid JSON")
    {
        WHEN("each is parsed")
        {
            auto const missing_field = merovingian::push::parse_notify_response(R"({})");
            auto const not_json = merovingian::push::parse_notify_response("not json");

            THEN("both fail closed with nullopt")
            {
                REQUIRE_FALSE(missing_field.has_value());
                REQUIRE_FALSE(not_json.has_value());
            }
        }
    }
}

SCENARIO("PushGatewayClient::notify fails closed when push delivery is disabled by config", "[push][push-gateway]")
{
    GIVEN("a client built from a PushConfig with delivery disabled (the default)")
    {
        auto outbound = merovingian::http::OutboundClient{};
        auto network = CountingDiscoveryNetwork{};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};
        auto const config = merovingian::config::PushConfig{};
        REQUIRE_FALSE(config.enabled);
        auto client = merovingian::push::PushGatewayClient{outbound, discovery, config};

        WHEN("notify is called")
        {
            auto const notification = merovingian::push::PushGatewayNotification{};
            auto const result = client.notify("https://push.example.org/_matrix/push/v1/notify", notification);

            THEN("no network resolution is attempted and the result reports disabled, not a transport failure")
            {
                REQUIRE(result.disabled);
                REQUIRE_FALSE(result.ok);
                REQUIRE(network.lookup_calls == 0U);
            }
        }
    }
}
