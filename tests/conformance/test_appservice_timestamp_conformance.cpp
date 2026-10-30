// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |            APPLICATION SERVICE API — TIMESTAMP MASSAGING                |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Timestamp massaging"      |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |        #timestamp-massaging                                             |
// |                                                                         |
// |  An application service may append `ts` to PUT /rooms/{roomId}/send/    |
// |  {eventType}/{txnId} and PUT /rooms/{roomId}/state/{eventType}/         |
// |  {stateKey} to set the event's origin_server_ts. The event is still     |
// |  appended at the tip of the DAG as though the timestamp were "now".     |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;

constexpr auto bridge_as_token = "ts-bridge-as-token-secret";
constexpr auto bridge_user = "@_ts_bridge_alice:example.org";
constexpr auto frozen_now_ms = std::int64_t{1'760'000'000'000};

[[nodiscard]] auto start_homeserver_with_bridge(std::filesystem::path const& registration_path)
    -> merovingian::homeserver::ClientServerStartResult
{
    {
        auto out = std::ofstream{registration_path, std::ios::binary};
        out << R"({
            "id": "ts-bridge",
            "url": null,
            "as_token": "ts-bridge-as-token-secret",
            "hs_token": "ts-bridge-hs-token-secret",
            "sender_localpart": "_ts_bot",
            "namespaces": {
                "users": [{"exclusive": true, "regex": "@_ts_bridge_.*"}],
                "aliases": [],
                "rooms": []
            }
        })";
    }
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
    config.appservice().registration_files = {registration_path.string()};
    return merovingian::homeserver::start_client_server(config);
}

// A homeserver with one bridge, its virtual user and a room that user created, on a server whose
// event clock reads `frozen_now_ms`.
struct TimestampFixture final
{
    std::filesystem::path registration_path;
    merovingian::homeserver::ClientServerStartResult started;
    std::string room_id{};

    TimestampFixture(TimestampFixture const&) = delete;
    auto operator=(TimestampFixture const&) -> TimestampFixture& = delete;
    TimestampFixture(TimestampFixture&&) = delete;
    auto operator=(TimestampFixture&&) -> TimestampFixture& = delete;

    explicit TimestampFixture(std::string_view name)
        : registration_path{std::filesystem::temp_directory_path() /
                            (std::string{"merovingian-ts-"} + std::string{name} + ".json")},
          started{start_homeserver_with_bridge(registration_path)}
    {
        REQUIRE(started.started);
        started.runtime.homeserver.test_frozen_event_clock_ms = frozen_now_ms;

        // AUTH-12: the service registers its virtual user before asserting it.
        REQUIRE(request("POST", "/_matrix/client/v3/register", bridge_as_token,
                        R"({"type":"m.login.application_service","inhibit_login":true,"username":"_ts_bridge_alice"})")
                    .response.status == 200U);
        auto const created = as_request("POST", "/_matrix/client/v3/createRoom", "{}");
        REQUIRE(created.response.status == 200U);
        auto const body = parse_object(created.response.body);
        auto const* id = string_member(body, "room_id");
        REQUIRE(id != nullptr);
        room_id = *id;
    }

    ~TimestampFixture()
    {
        std::filesystem::remove(registration_path);
    }

    [[nodiscard]] auto request(std::string_view method, std::string const& target, std::string const& token,
                               std::string const& body = {}) -> merovingian::homeserver::DispatchResult
    {
        return merovingian::homeserver::handle_client_server_request(started.runtime,
                                                                     {std::string{method}, target, token, body});
    }

    // A request authenticated as the appservice, acting as its virtual user.
    [[nodiscard]] auto as_request(std::string_view method, std::string target, std::string const& body = {})
        -> merovingian::homeserver::DispatchResult
    {
        target += target.find('?') == std::string::npos ? "?" : "&";
        target += std::string{"user_id="} + bridge_user;
        return request(method, target, bridge_as_token, body);
    }

    [[nodiscard]] auto send_path(std::string_view txn) const -> std::string
    {
        return "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + std::string{txn};
    }

    [[nodiscard]] auto state_path() const -> std::string
    {
        return "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic/";
    }

    // The origin_server_ts the room's copy of `event_id` carries, or nullopt when it cannot be read.
    [[nodiscard]] auto origin_server_ts_of(std::string const& event_id) -> std::optional<std::int64_t>
    {
        auto const fetched = as_request("GET", "/_matrix/client/v3/rooms/" + room_id + "/event/" + event_id);
        if (fetched.response.status != 200U)
        {
            return std::nullopt;
        }
        auto const body = parse_object(fetched.response.body);
        auto const* ts = int_member(body, "origin_server_ts");
        return ts == nullptr ? std::nullopt : std::optional<std::int64_t>{*ts};
    }

    [[nodiscard]] static auto event_id_of(merovingian::homeserver::DispatchResult const& result) -> std::string
    {
        auto const body = parse_object(result.response.body);
        auto const* id = string_member(body, "event_id");
        return id == nullptr ? std::string{} : *id;
    }

    // Event IDs in the order /messages?dir=b returns them (newest first).
    [[nodiscard]] auto timeline_newest_first() -> std::vector<std::string>
    {
        auto ids = std::vector<std::string>{};
        auto const messages = as_request("GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=100");
        REQUIRE(messages.response.status == 200U);
        auto const body = parse_object(messages.response.body);
        auto const* chunk = object_member_as_array(body, "chunk");
        REQUIRE(chunk != nullptr);
        for (auto const& entry : *chunk)
        {
            auto const* object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
            REQUIRE(object != nullptr);
            auto const* id = string_member(*object, "event_id");
            if (id != nullptr)
            {
                ids.push_back(*id);
            }
        }
        return ids;
    }
};

} // namespace

// Spec: Matrix Application Service API v1.19
// Endpoint / Section: Timestamp massaging
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#timestamp-massaging
SCENARIO("an appservice's ts on PUT /send sets the event's origin_server_ts",
         "[appservice][conformance][timestamp-massaging]")
{
    // Spec (Application Service API, "Timestamp massaging"): "When authenticating requests as an
    // application service, the caller can append a `ts` query string argument to change the
    // `origin_server_ts` of the resulting event."
    GIVEN("a bridge in a room it created, on a server whose clock reads a fixed time")
    {
        auto fixture = TimestampFixture{"send"};

        WHEN("the bridge sends a message with ts=1234567890123")
        {
            auto const sent = fixture.as_request("PUT", fixture.send_path("t1") + "?ts=1234567890123",
                                                 R"({"msgtype":"m.text","body":"massaged"})");

            THEN("the event is accepted and carries that origin_server_ts")
            {
                REQUIRE(sent.response.status == 200U);
                auto const stamped = fixture.origin_server_ts_of(TimestampFixture::event_id_of(sent));
                REQUIRE(stamped.has_value());
                CHECK(*stamped == 1'234'567'890'123);
            }
        }

        WHEN("the bridge sends a message with no ts")
        {
            auto const sent =
                fixture.as_request("PUT", fixture.send_path("t2"), R"({"msgtype":"m.text","body":"not massaged"})");

            THEN("the server's own clock supplies the origin_server_ts")
            {
                // Spec: "When not present, the server's behaviour is unchanged: the local system
                // time of the server will be used to provide a timestamp, representing 'now'."
                REQUIRE(sent.response.status == 200U);
                auto const stamped = fixture.origin_server_ts_of(TimestampFixture::event_id_of(sent));
                REQUIRE(stamped.has_value());
                CHECK(*stamped == frozen_now_ms);
            }
        }

        WHEN("the bridge sends one message with ts=0 and another at the top of the integer range")
        {
            auto const zero =
                fixture.as_request("PUT", fixture.send_path("t3") + "?ts=0", R"({"msgtype":"m.text","body":"epoch"})");
            auto const top = fixture.as_request("PUT", fixture.send_path("t4") + "?ts=9007199254740991",
                                                R"({"msgtype":"m.text","body":"far future"})");

            THEN("both are accepted with exactly those timestamps")
            {
                REQUIRE(zero.response.status == 200U);
                REQUIRE(top.response.status == 200U);
                CHECK(fixture.origin_server_ts_of(TimestampFixture::event_id_of(zero)) ==
                      std::optional<std::int64_t>{0});
                CHECK(fixture.origin_server_ts_of(TimestampFixture::event_id_of(top)) ==
                      std::optional<std::int64_t>{9'007'199'254'740'991});
            }
        }
    }
}

// Spec: Matrix Application Service API v1.19
// Endpoint / Section: Timestamp massaging
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#timestamp-massaging
SCENARIO("an appservice's ts on PUT /state sets the state event's origin_server_ts",
         "[appservice][conformance][timestamp-massaging]")
{
    // Spec (Application Service API, "Timestamp massaging"): the `ts` argument "is only valid on
    // the following endpoints: PUT /rooms/{roomId}/send/{eventType}/{txnId},
    // PUT /rooms/{roomId}/state/{eventType}/{stateKey}".
    GIVEN("a bridge in a room it created")
    {
        auto fixture = TimestampFixture{"state"};

        WHEN("the bridge sets the topic with ts=1500000000000")
        {
            auto const sent =
                fixture.as_request("PUT", fixture.state_path() + "?ts=1500000000000", R"({"topic":"massaged topic"})");

            THEN("the state event carries that origin_server_ts")
            {
                REQUIRE(sent.response.status == 200U);
                auto const stamped = fixture.origin_server_ts_of(TimestampFixture::event_id_of(sent));
                REQUIRE(stamped.has_value());
                CHECK(*stamped == 1'500'000'000'000);
            }
        }
    }
}

// Spec: Matrix Application Service API v1.19
// Endpoint / Section: Timestamp massaging
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#timestamp-massaging
SCENARIO("an appservice's ts that origin_server_ts cannot hold is a bad request",
         "[appservice][conformance][timestamp-massaging]")
{
    // Spec (Application Service API, "Timestamp massaging"): "Attempting to set the timestamp to
    // anything other than what is accepted by `origin_server_ts` should be rejected by the server
    // as a bad request." origin_server_ts is an `integer` (Client-Server API, Room Event Format),
    // and a Matrix integer lies in [-(2**53)+1, (2**53)-1] (Appendices, Canonical JSON).
    GIVEN("a bridge in a room it created")
    {
        auto fixture = TimestampFixture{"invalid"};
        auto const before = fixture.timeline_newest_first();

        WHEN("the bridge sends with a ts that is not an integer, is empty, or is outside the integer range")
        {
            auto const bad_values =
                std::vector<std::string>{"abc",
                                         "",
                                         "1.5",
                                         "1e3",
                                         "12abc",
                                         "+5",
                                         "0x10",
                                         "9007199254740992",
                                         "-9007199254740992",
                                         "9223372036854775808",
                                         "99999999999999999999"};
            auto sent_statuses = std::vector<unsigned>{};
            auto state_statuses = std::vector<unsigned>{};
            auto txn = 0;
            for (auto const& value : bad_values)
            {
                auto const sent = fixture.as_request(
                    "PUT", fixture.send_path("bad" + std::to_string(++txn)) + "?ts=" + value,
                    R"({"msgtype":"m.text","body":"x"})");
                sent_statuses.push_back(sent.response.status);
                auto const state =
                    fixture.as_request("PUT", fixture.state_path() + "?ts=" + value, R"({"topic":"x"})");
                state_statuses.push_back(state.response.status);
            }

            THEN("every send and state request is refused with 400 and nothing is stored")
            {
                for (auto i = std::size_t{0}; i < bad_values.size(); ++i)
                {
                    INFO("ts=" << bad_values[i]);
                    CHECK(sent_statuses[i] == 400U);
                    CHECK(state_statuses[i] == 400U);
                }
                CHECK(fixture.timeline_newest_first() == before);
            }
        }

        WHEN("the bridge sends with a ts at the negative end of the integer range")
        {
            auto const sent = fixture.as_request("PUT", fixture.send_path("neg") + "?ts=-9007199254740991",
                                                 R"({"msgtype":"m.text","body":"x"})");

            THEN("it is accepted with exactly that timestamp")
            {
                REQUIRE(sent.response.status == 200U);
                CHECK(fixture.origin_server_ts_of(TimestampFixture::event_id_of(sent)) ==
                      std::optional<std::int64_t>{-9'007'199'254'740'991});
            }
        }
    }
}

// Spec: Matrix Application Service API v1.19
// Endpoint / Section: Timestamp massaging
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#timestamp-massaging
SCENARIO("a ts from anyone but an appservice does not change origin_server_ts",
         "[appservice][conformance][timestamp-massaging]")
{
    // Spec (Application Service API, "Timestamp massaging"): the argument is read "when
    // authenticating requests as an application service". The spec does not say what any other
    // caller's `ts` does; the server leaves such a request exactly as it would be without it.
    GIVEN("an ordinary user in a room of their own")
    {
        auto fixture = TimestampFixture{"ordinary"};
        auto const registered = fixture.request("POST", "/_matrix/client/v3/register", {},
                                                registration_json("plainuser", "CorrectHorse7!"));
        REQUIRE(registered.response.status == 200U);
        auto const registered_body = parse_object(registered.response.body);
        auto const* token = string_member(registered_body, "access_token");
        REQUIRE(token != nullptr);
        auto const room = fixture.request("POST", "/_matrix/client/v3/createRoom", *token, "{}");
        REQUIRE(room.response.status == 200U);
        auto const room_body = parse_object(room.response.body);
        auto const* own_room = string_member(room_body, "room_id");
        REQUIRE(own_room != nullptr);

        WHEN("the user sends a message and sets the topic, each with ts=42")
        {
            auto const sent = fixture.request("PUT",
                                              "/_matrix/client/v3/rooms/" + *own_room + "/send/m.room.message/u1?ts=42",
                                              *token, R"({"msgtype":"m.text","body":"hello"})");
            auto const topic = fixture.request(
                "PUT", "/_matrix/client/v3/rooms/" + *own_room + "/state/m.room.topic/?ts=42", *token,
                R"({"topic":"hello"})");

            THEN("both events carry the server's own timestamp")
            {
                REQUIRE(sent.response.status == 200U);
                REQUIRE(topic.response.status == 200U);
                for (auto const& result : {sent, topic})
                {
                    auto const fetched = fixture.request("GET",
                                                         "/_matrix/client/v3/rooms/" + *own_room + "/event/" +
                                                             TimestampFixture::event_id_of(result),
                                                         *token);
                    REQUIRE(fetched.response.status == 200U);
                    auto const body = parse_object(fetched.response.body);
                    auto const* ts = int_member(body, "origin_server_ts");
                    REQUIRE(ts != nullptr);
                    CHECK(*ts == frozen_now_ms);
                }
            }
        }
    }
}

// Spec: Matrix Application Service API v1.19
// Endpoint / Section: Timestamp massaging
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#timestamp-massaging
SCENARIO("an appservice's ts on an endpoint that does not support it does not change origin_server_ts",
         "[appservice][conformance][timestamp-massaging]")
{
    // Spec (Application Service API, "Timestamp massaging"): "Other endpoints, such as `/kick`, do
    // not support `ts`: instead, callers can use the `PUT /state` endpoint to mimic the behaviour
    // of the other APIs."
    GIVEN("a bridge in a room it created, and a message it sent")
    {
        auto fixture = TimestampFixture{"other"};
        auto const message =
            fixture.as_request("PUT", fixture.send_path("m1"), R"({"msgtype":"m.text","body":"to redact"})");
        REQUIRE(message.response.status == 200U);

        WHEN("the bridge redacts the message through PUT /redact with ts=77")
        {
            auto const redaction = fixture.as_request("PUT",
                                                      "/_matrix/client/v3/rooms/" + fixture.room_id + "/redact/" +
                                                          TimestampFixture::event_id_of(message) + "/r1?ts=77",
                                                      R"({"reason":"test"})");

            THEN("the redaction event carries the server's own timestamp")
            {
                REQUIRE(redaction.response.status == 200U);
                CHECK(fixture.origin_server_ts_of(TimestampFixture::event_id_of(redaction)) ==
                      std::optional<std::int64_t>{frozen_now_ms});
            }
        }
    }
}

// Spec: Matrix Application Service API v1.19
// Endpoint / Section: Timestamp massaging
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#timestamp-massaging
SCENARIO("a massaged timestamp does not change the order in which events are appended",
         "[appservice][conformance][timestamp-massaging]")
{
    // Spec (Application Service API, "Timestamp massaging"): "Changing the time of an event does
    // not change the server-side (DAG) ordering for the event. The event will still be appended at
    // the tip of the DAG as though the timestamp was set to 'now'."
    GIVEN("a bridge in a room it created")
    {
        auto fixture = TimestampFixture{"order"};

        WHEN("the bridge sends three messages whose timestamps run 3000, 1000, 2000")
        {
            auto const first = fixture.as_request("PUT", fixture.send_path("o1") + "?ts=3000",
                                                  R"({"msgtype":"m.text","body":"first"})");
            auto const second = fixture.as_request("PUT", fixture.send_path("o2") + "?ts=1000",
                                                   R"({"msgtype":"m.text","body":"second"})");
            auto const third = fixture.as_request("PUT", fixture.send_path("o3") + "?ts=2000",
                                                  R"({"msgtype":"m.text","body":"third"})");
            REQUIRE(first.response.status == 200U);
            REQUIRE(second.response.status == 200U);
            REQUIRE(third.response.status == 200U);

            THEN("the room's timeline holds them in the order they were sent")
            {
                auto const newest_first = fixture.timeline_newest_first();
                REQUIRE(newest_first.size() >= 3U);
                CHECK(newest_first[0] == TimestampFixture::event_id_of(third));
                CHECK(newest_first[1] == TimestampFixture::event_id_of(second));
                CHECK(newest_first[2] == TimestampFixture::event_id_of(first));
            }
        }
    }
}
