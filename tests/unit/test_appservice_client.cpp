// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |        APPLICATION SERVICE API CLIENT — PURE HELPER UNIT TESTS          |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Pushing events"          |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  Covers the network-free transaction-body builder and the              |
// |  url:null "disabled" fast path, which never reaches the transport.     |
// |  Live delivery against a mock appservice belongs in                    |
// |  conformance/integration, matching the push-gateway-client precedent.  |
// +-------------------------------------------------------------------------+

#include "merovingian/appservice/appservice_client.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"

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

// Minimal ServerDiscoveryNetwork test double — never actually exercised by
// these pure-builder/disabled-path scenarios, but AppserviceClient's
// constructor requires a CachedServerDiscovery to wrap.
struct StubDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
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
        return {false, {}, "not exercised"};
    }
};

} // namespace

SCENARIO("building a transaction request body", "[appservice][client]")
{
    GIVEN("a transaction with two events, one of them a state event")
    {
        auto transaction = merovingian::appservice::AppserviceTransaction{};
        transaction.txn_id = "42";
        transaction.events.push_back({R"({"body":"hello","msgtype":"m.text"})", "$event1:example.org", 1234567890U,
                                      "!room:example.org", "@alice:example.org", std::nullopt, "m.room.message"});
        transaction.events.push_back({R"({"membership":"join"})", "$event2:example.org", 1234567891U,
                                      "!room:example.org", "@alice:example.org",
                                      std::optional<std::string>{"@alice:example.org"}, "m.room.member"});

        WHEN("the request body is built")
        {
            auto const body = merovingian::appservice::build_transaction_request_body(transaction);
            auto const root = parse_object(body);

            THEN("it carries an events array shaped per the spec's ClientEvent")
            {
                auto const* events_value = object_member(root, "events");
                REQUIRE(events_value != nullptr);
                auto const* events_array = std::get_if<merovingian::canonicaljson::Array>(&events_value->storage());
                REQUIRE(events_array != nullptr);
                REQUIRE(events_array->size() == 2U);

                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&(*events_array)[0].storage());
                REQUIRE(first != nullptr);
                auto const* first_event_id = object_member(*first, "event_id");
                REQUIRE(first_event_id != nullptr);
                CHECK(std::get<std::string>(first_event_id->storage()) == "$event1:example.org");
                // A non-state event must NOT carry a state_key member at all —
                // "the application service should distinguish state events
                // from message events via the presence of a state_key".
                CHECK(object_member(*first, "state_key") == nullptr);

                auto const* second = std::get_if<merovingian::canonicaljson::Object>(&(*events_array)[1].storage());
                REQUIRE(second != nullptr);
                auto const* second_state_key = object_member(*second, "state_key");
                REQUIRE(second_state_key != nullptr);
                CHECK(std::get<std::string>(second_state_key->storage()) == "@alice:example.org");
            }
        }
    }

    GIVEN("a transaction with no events")
    {
        auto const transaction = merovingian::appservice::AppserviceTransaction{"1", {}};

        WHEN("the request body is built")
        {
            auto const body = merovingian::appservice::build_transaction_request_body(transaction);
            auto const root = parse_object(body);

            THEN("it still carries an (empty) events array, never omitting the required field")
            {
                auto const* events_value = object_member(root, "events");
                REQUIRE(events_value != nullptr);
                auto const* events_array = std::get_if<merovingian::canonicaljson::Array>(&events_value->storage());
                REQUIRE(events_array != nullptr);
                CHECK(events_array->empty());
            }
        }
    }
}

SCENARIO("AppserviceClient never attempts a network call for a url:null appservice", "[appservice][client]")
{
    GIVEN("a registration with url set to nullopt (spec: 'no traffic is required')")
    {
        auto registration = merovingian::appservice::AppserviceRegistration{};
        registration.id = "no-traffic";
        registration.url = std::nullopt;
        registration.sender_localpart = "bot";

        auto outbound = merovingian::http::OutboundClient{};
        auto network = StubDiscoveryNetwork{};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};
        auto client = merovingian::appservice::AppserviceClient{outbound, discovery};

        WHEN("send_transaction is called")
        {
            auto const result =
                client.send_transaction(registration, merovingian::appservice::AppserviceTransaction{"1", {}});

            THEN("it reports disabled without touching the (unreachable, stubbed) network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
            }
        }

        WHEN("query_user is called")
        {
            auto const result = client.query_user(registration, "@someone:example.org");

            THEN("it reports disabled without touching the network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
            }
        }

        WHEN("query_room_alias is called")
        {
            auto const result = client.query_room_alias(registration, "#somewhere:example.org");

            THEN("it reports disabled without touching the network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
            }
        }
    }
}
