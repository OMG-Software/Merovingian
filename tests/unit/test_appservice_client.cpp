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
#include "merovingian/config/config.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
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

// Parses `json` (object or array root) and returns the whole Value tree,
// for the parse_thirdparty_*_response scenarios below, which accept
// whichever root shape their input requires.
[[nodiscard]] auto parse_object_value(std::string_view json) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_json(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
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

struct ResolvableDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
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
        return {true, {"127.0.0.1"}, {}};
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

        WHEN("query_thirdparty_protocol is called")
        {
            auto const result = client.query_thirdparty_protocol(registration, "irc");

            THEN("it reports disabled without touching the network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
                CHECK_FALSE(result.found);
            }
        }

        WHEN("query_thirdparty_location_by_alias is called")
        {
            auto const result =
                client.query_thirdparty_location_by_alias(registration, "#freenode_#matrix:example.org");

            THEN("it reports disabled without touching the network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
                CHECK(result.locations.empty());
            }
        }

        WHEN("query_thirdparty_location_by_protocol is called")
        {
            auto const result = client.query_thirdparty_location_by_protocol(registration, "irc", {});

            THEN("it reports disabled without touching the network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
                CHECK(result.locations.empty());
            }
        }

        WHEN("query_thirdparty_user_by_userid is called")
        {
            auto const result = client.query_thirdparty_user_by_userid(registration, "@_irc_bob:example.org");

            THEN("it reports disabled without touching the network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
                CHECK(result.users.empty());
            }
        }

        WHEN("query_thirdparty_user_by_protocol is called")
        {
            auto const result = client.query_thirdparty_user_by_protocol(registration, "irc", {});

            THEN("it reports disabled without touching the network")
            {
                CHECK(result.disabled);
                CHECK_FALSE(result.ok);
                CHECK(result.users.empty());
            }
        }
    }
}

SCENARIO("AppserviceClient applies configured bounds to every outbound request", "[appservice][client][limits]")
{
    GIVEN("an appservice request policy and a local resolution stub")
    {
        auto outbound = merovingian::http::OutboundClient{};
        auto network = ResolvableDiscoveryNetwork{};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};
        auto policy = merovingian::config::AppserviceConfig{};
        policy.connect_timeout_seconds = 3U;
        policy.total_timeout_seconds = 7U;
        policy.response_max_size = "2KiB";
        auto observed = std::optional<merovingian::http::OutboundRequest>{};
        auto client = merovingian::appservice::AppserviceClient{
            outbound, discovery, policy, [&observed](merovingian::http::OutboundRequest const& request) {
                observed = request;
                auto result = merovingian::http::OutboundResult{};
                result.ok = true;
                result.response.status = 200U;
                return result;
            }};
        auto registration = merovingian::appservice::AppserviceRegistration{};
        registration.id = "configured";
        registration.url = "http://127.0.0.1:1234";

        WHEN("the client performs an appservice query")
        {
            auto const result = client.query_user(registration, "@bot:example.org");

            THEN("the outbound request carries the configured deadlines and finite response bound")
            {
                REQUIRE(result.ok);
                REQUIRE(observed.has_value());
                CHECK(observed->connect_timeout_seconds == 3U);
                CHECK(observed->total_timeout_seconds == 7U);
                CHECK(observed->max_response_body_bytes == 2048U);
            }
        }
    }
}

// Spec: Application Service API v1.19, "Pushing ephemeral data": the transaction request body carries an
// `ephemeral` array alongside the required `events` array when the registration set receive_ephemeral.
SCENARIO("a transaction request body carries ephemeral events only when there are some", "[appservice][client][r08]")
{
    GIVEN("a transaction with one event and two ephemeral events")
    {
        auto transaction = merovingian::appservice::AppserviceTransaction{};
        transaction.txn_id = "7";
        transaction.events.push_back({R"({"body":"hi"})", "$e:example.org", 1U, "!r:example.org", "@alice:example.org",
                                      std::nullopt, "m.room.message"});
        transaction.ephemeral_json = {
            R"({"content":{"user_ids":["@a:example.org"]},"room_id":"!r:example.org","type":"m.typing"})",
            R"({"content":{"presence":"online"},"sender":"@a:example.org","type":"m.presence"})",
        };

        WHEN("the request body is built")
        {
            auto const body = parse_object(merovingian::appservice::build_transaction_request_body(transaction));

            THEN("events and ephemeral are both arrays, ephemeral in the order given")
            {
                auto const* events = object_member(body, "events");
                auto const* ephemeral = object_member(body, "ephemeral");
                REQUIRE(events != nullptr);
                REQUIRE(ephemeral != nullptr);
                auto const* ephemeral_array = std::get_if<merovingian::canonicaljson::Array>(&ephemeral->storage());
                REQUIRE(ephemeral_array != nullptr);
                REQUIRE(ephemeral_array->size() == 2U);
                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&(*ephemeral_array)[0].storage());
                REQUIRE(first != nullptr);
                auto const* type = object_member(*first, "type");
                REQUIRE(type != nullptr);
                CHECK(*std::get_if<std::string>(&type->storage()) == "m.typing");
            }
        }
    }

    GIVEN("a transaction with no ephemeral events")
    {
        auto transaction = merovingian::appservice::AppserviceTransaction{};
        transaction.txn_id = "8";

        WHEN("the request body is built")
        {
            auto const body = parse_object(merovingian::appservice::build_transaction_request_body(transaction));

            THEN("the optional ephemeral property is absent and events is an empty array")
            {
                CHECK(object_member(body, "ephemeral") == nullptr);
                REQUIRE(object_member(body, "events") != nullptr);
            }
        }
    }

    GIVEN("an ephemeral element that is not valid JSON")
    {
        auto transaction = merovingian::appservice::AppserviceTransaction{};
        transaction.txn_id = "9";
        transaction.ephemeral_json = {"{not json", R"({"type":"m.typing","room_id":"!r:x","content":{}})"};

        WHEN("the request body is built")
        {
            auto const body = parse_object(merovingian::appservice::build_transaction_request_body(transaction));

            THEN("it is skipped and the valid element still travels")
            {
                auto const* ephemeral = object_member(body, "ephemeral");
                REQUIRE(ephemeral != nullptr);
                auto const* ephemeral_array = std::get_if<merovingian::canonicaljson::Array>(&ephemeral->storage());
                REQUIRE(ephemeral_array != nullptr);
                CHECK(ephemeral_array->size() == 1U);
            }
        }
    }
}

// Spec: Application Service API v1.19, "Pinging", POST /_matrix/app/v1/ping: "called by the homeserver to
// ensure that the connection works and the hs_token the homeserver has is correct", with the request body
// {"transaction_id": ...} copied from the client call.
SCENARIO("pinging an appservice classifies every way the call can end", "[appservice][client][ping]")
{
    GIVEN("an appservice client whose transport is a recording stub")
    {
        auto outbound = merovingian::http::OutboundClient{};
        auto network = ResolvableDiscoveryNetwork{};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};
        auto observed = std::optional<merovingian::http::OutboundRequest>{};
        auto answer = merovingian::http::OutboundResult{};
        answer.ok = true;
        answer.response.status = 200U;
        auto client = merovingian::appservice::AppserviceClient{
            outbound, discovery, merovingian::config::AppserviceConfig{},
            [&observed, &answer](merovingian::http::OutboundRequest const& request) {
                observed = request;
                return answer;
            }};
        auto parsed_registration = merovingian::appservice::parse_registration_json(R"({
            "id": "bridge",
            "url": "http://127.0.0.1:1234",
            "as_token": "the-as-token",
            "hs_token": "the-hs-token",
            "sender_localpart": "_bridge_bot",
            "namespaces": {"users": [], "aliases": [], "rooms": []}
        })");
        REQUIRE(parsed_registration.value.has_value());
        auto& registration = *parsed_registration.value;

        WHEN("the appservice answers 200")
        {
            auto const result = client.ping(registration, "meow");

            THEN("the ping succeeds and carried the hs_token, the path and the transaction id")
            {
                REQUIRE(result.ok());
                REQUIRE(observed.has_value());
                CHECK(observed->method == "POST");
                CHECK(observed->url == "http://127.0.0.1:1234/_matrix/app/v1/ping");
                CHECK(observed->body == R"({"transaction_id":"meow"})");
                auto const authorization =
                    std::ranges::find_if(observed->headers, [](merovingian::http::OutboundHeader const& header) {
                        return header.name == "Authorization";
                    });
                REQUIRE(authorization != observed->headers.end());
                CHECK(authorization->value == "Bearer the-hs-token");
                CHECK(result.duration_ms >= 0);
            }
        }

        WHEN("the appservice is pinged without a transaction id")
        {
            auto const result = client.ping(registration, std::nullopt);

            THEN("the request body is an empty object")
            {
                REQUIRE(result.ok());
                REQUIRE(observed.has_value());
                CHECK(observed->body == "{}");
            }
        }

        WHEN("the appservice is pinged with an empty transaction id")
        {
            auto const result = client.ping(registration, std::string{});

            THEN("the empty transaction id is copied into the request body, not dropped")
            {
                REQUIRE(result.ok());
                REQUIRE(observed.has_value());
                CHECK(observed->body == R"({"transaction_id":""})");
            }
        }

        WHEN("the appservice rejects the hs_token with 403")
        {
            answer.response.status = 403U;
            answer.response.body = R"({"errcode":"M_FORBIDDEN"})";
            auto const result = client.ping(registration, "meow");

            THEN("the failure is bad_status and carries the appservice's status and body")
            {
                CHECK(result.failure == merovingian::appservice::AppservicePingFailure::bad_status);
                CHECK(result.status == 403U);
                CHECK(result.body == R"({"errcode":"M_FORBIDDEN"})");
            }
        }

        WHEN("the appservice answers with a very long body")
        {
            answer.response.status = 500U;
            answer.response.body = std::string(merovingian::appservice::max_ping_body_bytes * 4U, 'x');
            auto const result = client.ping(registration, std::nullopt);

            THEN("the body kept for the error is bounded")
            {
                CHECK(result.failure == merovingian::appservice::AppservicePingFailure::bad_status);
                CHECK(result.body.size() == merovingian::appservice::max_ping_body_bytes);
            }
        }

        WHEN("the appservice answers with a redirect, which the transport refuses to follow")
        {
            answer.ok = false;
            answer.error = merovingian::http::OutboundError::redirect_rejected;
            answer.response.status = 302U;
            auto const result = client.ping(registration, std::nullopt);

            THEN("it is a bad status (the appservice did answer), not a failed connection")
            {
                CHECK(result.failure == merovingian::appservice::AppservicePingFailure::bad_status);
                CHECK(result.status == 302U);
            }
        }

        WHEN("the transport times out")
        {
            answer.ok = false;
            answer.error = merovingian::http::OutboundError::timeout;
            answer.response.status = 0U;
            auto const result = client.ping(registration, std::nullopt);

            THEN("the failure is connection_timeout")
            {
                CHECK(result.failure == merovingian::appservice::AppservicePingFailure::connection_timeout);
            }
        }

        WHEN("the transport cannot connect, or TLS fails, or the reply is oversize")
        {
            answer.ok = false;
            answer.response.status = 0U;

            THEN("each is connection_failed")
            {
                for (auto const error : {merovingian::http::OutboundError::connection_failed,
                                         merovingian::http::OutboundError::tls_verification_failed,
                                         merovingian::http::OutboundError::response_too_large,
                                         merovingian::http::OutboundError::network_error})
                {
                    answer.error = error;
                    CHECK(client.ping(registration, std::nullopt).failure ==
                          merovingian::appservice::AppservicePingFailure::connection_failed);
                }
            }
        }

        WHEN("the registration has url null")
        {
            registration.url = std::nullopt;
            observed.reset();
            auto const result = client.ping(registration, "meow");

            THEN("the failure is url_not_set and nothing was sent")
            {
                CHECK(result.failure == merovingian::appservice::AppservicePingFailure::url_not_set);
                CHECK_FALSE(observed.has_value());
            }
        }
    }
}

// +-------------------------------------------------------------------------+
// |     THIRD-PARTY LOOKUP RESPONSE PARSING — BOUNDED, DEFENSIVE, PURE      |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19 "Third-party networks"     |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  parse_thirdparty_{protocol,location,user}_response are network-free   |
// |  and unit-testable in isolation, matching build_transaction_request_   |
// |  body's precedent above. src/appservice/AGENTS.md: "a bridge is not a  |
// |  trusted peer" — every field is type-checked and bounded, and a        |
// |  malformed entry is dropped rather than propagated.                    |
// +-------------------------------------------------------------------------+

SCENARIO("parsing a well-formed thirdparty Protocol response", "[appservice][client][thirdparty]")
{
    GIVEN("a Protocol JSON body shaped exactly like the spec's own example")
    {
        auto const body = R"({
            "field_types": {
                "channel": {"placeholder": "#foobar", "regexp": "#[^\\s]+"},
                "network": {"placeholder": "irc.example.org", "regexp": "([a-z0-9]+\\.)*[a-z0-9]+"}
            },
            "icon": "mxc://example.org/aBcDeFgH",
            "instances": [
                {"desc": "Freenode", "fields": {"network": "freenode"}, "icon": "mxc://example.org/JkLmNoPq", "network_id": "freenode"}
            ],
            "location_fields": ["network", "channel"],
            "user_fields": ["network", "nickname"]
        })";
        auto const parsed = parse_object_value(body);

        WHEN("parse_thirdparty_protocol_response is called")
        {
            auto const result = merovingian::appservice::parse_thirdparty_protocol_response(parsed);

            THEN("every field round-trips")
            {
                REQUIRE(result.has_value());
                CHECK(result->icon == "mxc://example.org/aBcDeFgH");
                REQUIRE(result->field_types.size() == 2U);
                REQUIRE(result->instances.size() == 1U);
                CHECK(result->instances[0].desc == "Freenode");
                CHECK(result->instances[0].network_id == "freenode");
                CHECK(result->instances[0].icon == "mxc://example.org/JkLmNoPq");
                REQUIRE(result->location_fields.size() == 2U);
                CHECK(result->location_fields[0] == "network");
                CHECK(result->location_fields[1] == "channel");
                REQUIRE(result->user_fields.size() == 2U);
            }
        }
    }
}

SCENARIO("parsing a thirdparty Protocol response whose root is not an object", "[appservice][client][thirdparty]")
{
    GIVEN("a JSON array where an object was required")
    {
        auto const parsed = merovingian::canonicaljson::parse_json("[]");
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);

        WHEN("parse_thirdparty_protocol_response is called")
        {
            auto const result = merovingian::appservice::parse_thirdparty_protocol_response(parsed.value);

            THEN("it reports no protocol rather than a default-constructed one")
            {
                CHECK_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("parsing thirdparty Location/User arrays drops entries missing a required identifying string",
         "[appservice][client][thirdparty]")
{
    GIVEN("a Location array where one entry is missing the required 'protocol' field")
    {
        auto const body = R"([
            {"alias": "#freenode_#matrix:matrix.org", "fields": {"channel": "#matrix"}, "protocol": "irc"},
            {"alias": "#missing-protocol:matrix.org", "fields": {}}
        ])";
        auto const parsed = parse_object_value(body);

        WHEN("parse_thirdparty_location_response is called")
        {
            auto const result = merovingian::appservice::parse_thirdparty_location_response(parsed);

            THEN("only the well-formed entry survives")
            {
                REQUIRE(result.size() == 1U);
                CHECK(result[0].alias == "#freenode_#matrix:matrix.org");
                CHECK(result[0].protocol == "irc");
            }
        }
    }

    GIVEN("a User array where one entry has a non-string userid")
    {
        auto const body = R"([
            {"fields": {"user": "jim"}, "protocol": "gitter", "userid": "@_gitter_jim:matrix.org"},
            {"fields": {"user": "bad"}, "protocol": "gitter", "userid": 12345}
        ])";
        auto const parsed = parse_object_value(body);

        WHEN("parse_thirdparty_user_response is called")
        {
            auto const result = merovingian::appservice::parse_thirdparty_user_response(parsed);

            THEN("only the well-formed entry survives")
            {
                REQUIRE(result.size() == 1U);
                CHECK(result[0].userid == "@_gitter_jim:matrix.org");
            }
        }
    }
}

SCENARIO("a Location entry with a non-object 'fields' member survives with fields defaulted to empty",
         "[appservice][client][thirdparty]")
{
    // `fields` is Required by the spec, but it is not one of the identifying
    // strings (alias/protocol) — a malformed `fields` value is treated the
    // same as an absent one (empty object) rather than sinking the whole
    // entry, since alias/protocol alone are enough to identify the result.
    GIVEN("a Location entry whose 'fields' member is a string instead of an object")
    {
        auto const body = R"([
            {"alias": "#odd:matrix.org", "fields": "not an object", "protocol": "irc"}
        ])";
        auto const parsed = parse_object_value(body);

        WHEN("parse_thirdparty_location_response is called")
        {
            auto const result = merovingian::appservice::parse_thirdparty_location_response(parsed);

            THEN("the entry survives with an empty fields object")
            {
                REQUIRE(result.size() == 1U);
                CHECK(result[0].alias == "#odd:matrix.org");
                CHECK(result[0].protocol == "irc");
                CHECK(result[0].fields.empty());
            }
        }
    }
}

SCENARIO("thirdparty fields objects drop non-string members instead of trusting them through",
         "[appservice][client][thirdparty][security]")
{
    // Every Location.fields/User.fields example in the spec carries plain
    // string values. A hostile or buggy bridge returning a nested object,
    // array, or number as a field value must not have that value silently
    // forwarded to the client as if it were a validated string.
    GIVEN("a Location entry whose fields object mixes string and non-string members")
    {
        auto const body = R"([{
            "alias": "#chan:matrix.org",
            "fields": {"channel": "#chan", "malicious": {"nested": "object"}, "count": 5, "flag": true},
            "protocol": "irc"
        }])";
        auto const parsed = parse_object_value(body);

        WHEN("parse_thirdparty_location_response is called")
        {
            auto const result = merovingian::appservice::parse_thirdparty_location_response(parsed);

            THEN("only the string-valued member is kept")
            {
                REQUIRE(result.size() == 1U);
                REQUIRE(result[0].fields.size() == 1U);
                CHECK(result[0].fields[0].key == "channel");
                REQUIRE(result[0].fields[0].value != nullptr);
                auto const* str_value = std::get_if<std::string>(&result[0].fields[0].value->storage());
                REQUIRE(str_value != nullptr);
                CHECK(*str_value == "#chan");
            }
        }
    }
}
