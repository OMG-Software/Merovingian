// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |   APPLICATION SERVICE DELIVERY — INTEREST, ROOM CREATION, EPHEMERAL      |
// |   DATA, QUEUE CAP AND THIRD-PARTY ADMISSION (conformance audit wave 3)   |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19                            |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  These drive a real loopback mock appservice and assert on the bytes it  |
// |  actually received. The drainer is called directly with a stepped clock, |
// |  so no scenario sleeps and no PeriodicJob thread runs.                   |
// +-------------------------------------------------------------------------+

#include "../support/appservice_test_config.hpp"
#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/mock_appservice.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/homeserver/appservice_delivery.hpp"
#include "merovingian/homeserver/appservice_ephemeral.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/stop_flag.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using merovingian::homeserver::ClientServerRuntime;
using merovingian::tests::MockAppservice;
using merovingian::tests::TestAppservice;

constexpr auto password = std::string_view{"CorrectHorse7!"};

[[nodiscard]] auto call(ClientServerRuntime& runtime, std::string method, std::string target, std::string token,
                        std::string body = {}, std::string client_address = {})
{
    auto request = merovingian::homeserver::LocalHttpRequest{};
    request.method = std::move(method);
    request.target = std::move(target);
    request.access_token = std::move(token);
    request.body = std::move(body);
    request.remote_addr = std::move(client_address);
    return merovingian::homeserver::handle_client_server_request(runtime, request);
}

[[nodiscard]] auto string_in(std::string const& json, std::string const& key) -> std::string
{
    auto const object = merovingian::tests::parse_object(json);
    auto const* value = merovingian::tests::string_member(object, key);
    REQUIRE(value != nullptr);
    return *value;
}

[[nodiscard]] auto register_human(ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    auto const registered = call(runtime, "POST", "/_matrix/client/v3/register", {},
                                 merovingian::tests::registration_json(localpart, std::string{password}));
    REQUIRE(registered.response.status == 200U);
    return string_in(registered.response.body, "access_token");
}

// The appservice creates one of its virtual users, which is how the service makes a user that
// identity assertion (and a room invite) can name.
auto register_virtual_user(ClientServerRuntime& runtime, TestAppservice const& appservice, std::string const& localpart)
    -> void
{
    auto const registered =
        call(runtime, "POST", "/_matrix/client/v3/register", appservice.as_token(),
             R"({"type":"m.login.application_service","inhibit_login":true,"username":")" + localpart + R"("})");
    REQUIRE(registered.response.status == 200U);
}

[[nodiscard]] auto create_room(ClientServerRuntime& runtime, std::string const& token, std::string const& body = "{}")
    -> std::string
{
    auto const created = call(runtime, "POST", "/_matrix/client/v3/createRoom", token, body);
    REQUIRE(created.response.status == 200U);
    return string_in(created.response.body, "room_id");
}

[[nodiscard]] auto send_message(ClientServerRuntime& runtime, std::string const& token, std::string const& room_id,
                                std::string const& text) -> std::string
{
    auto const sent = call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-" + text,
                           token, R"({"msgtype":"m.text","body":")" + text + R"("})");
    REQUIRE(sent.response.status == 200U);
    return string_in(sent.response.body, "event_id");
}

// Steps a synthetic clock so the drainer's back-off never makes a scenario sleep.
struct SteppedClock final
{
    std::chrono::steady_clock::time_point now{std::chrono::steady_clock::now()};

    auto drain(ClientServerRuntime& runtime) -> void
    {
        now += 10min;
        auto const stop = merovingian::homeserver::StopFlag{};
        std::ignore = merovingian::homeserver::drain_appservice_queues(runtime.homeserver, stop, now);
    }
};

struct SeenEvent final
{
    std::string type{};
    std::string sender{};
    std::string room_id{};
    std::optional<std::string> state_key{};
    std::string membership{};
};

// Every event in every transaction the mock received, in arrival order.
[[nodiscard]] auto events_received(MockAppservice const& mock) -> std::vector<SeenEvent>
{
    auto seen = std::vector<SeenEvent>{};
    for (auto const& request : mock.requests_to("/_matrix/app/v1/transactions/"))
    {
        auto const body = merovingian::tests::parse_object(request.body);
        auto const* events = merovingian::tests::object_member_as_array(body, "events");
        REQUIRE(events != nullptr);
        for (auto const& entry : *events)
        {
            auto const* event = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
            REQUIRE(event != nullptr);
            auto out = SeenEvent{};
            if (auto const* type = merovingian::tests::string_member(*event, "type"); type != nullptr)
            {
                out.type = *type;
            }
            if (auto const* sender = merovingian::tests::string_member(*event, "sender"); sender != nullptr)
            {
                out.sender = *sender;
            }
            if (auto const* room_id = merovingian::tests::string_member(*event, "room_id"); room_id != nullptr)
            {
                out.room_id = *room_id;
            }
            if (auto const* state_key = merovingian::tests::string_member(*event, "state_key"); state_key != nullptr)
            {
                out.state_key = *state_key;
            }
            if (auto const* content = merovingian::tests::object_member_as_object(*event, "content");
                content != nullptr)
            {
                if (auto const* membership = merovingian::tests::string_member(*content, "membership");
                    membership != nullptr)
                {
                    out.membership = *membership;
                }
            }
            seen.push_back(std::move(out));
        }
    }
    return seen;
}

struct SeenEphemeral final
{
    std::string type{};
    std::string room_id{};
    std::string sender{};
    std::string raw_content{};
};

// Every ephemeral event the mock received after its first `skip_transactions` transactions.
[[nodiscard]] auto ephemeral_received(MockAppservice const& mock, std::size_t skip_transactions = 0U)
    -> std::vector<SeenEphemeral>
{
    auto seen = std::vector<SeenEphemeral>{};
    auto transaction_index = std::size_t{0U};
    for (auto const& request : mock.requests_to("/_matrix/app/v1/transactions/"))
    {
        if (transaction_index++ < skip_transactions)
        {
            continue;
        }
        auto const body = merovingian::tests::parse_object(request.body);
        auto const* ephemeral = merovingian::tests::object_member_as_array(body, "ephemeral");
        if (ephemeral == nullptr)
        {
            continue;
        }
        for (auto const& entry : *ephemeral)
        {
            auto const* event = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
            REQUIRE(event != nullptr);
            auto out = SeenEphemeral{};
            if (auto const* type = merovingian::tests::string_member(*event, "type"); type != nullptr)
            {
                out.type = *type;
            }
            if (auto const* room_id = merovingian::tests::string_member(*event, "room_id"); room_id != nullptr)
            {
                out.room_id = *room_id;
            }
            if (auto const* sender = merovingian::tests::string_member(*event, "sender"); sender != nullptr)
            {
                out.sender = *sender;
            }
            if (auto const* content = merovingian::tests::object_member(*event, "content"); content != nullptr)
            {
                out.raw_content =
                    merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{*content}).output;
            }
            seen.push_back(std::move(out));
        }
    }
    return seen;
}

[[nodiscard]] auto transaction_count(MockAppservice const& mock) -> std::size_t
{
    return mock.requests_to("/_matrix/app/v1/transactions/").size();
}

} // namespace

// ===========================================================================
// R07: interest follows the spec's definition
// ===========================================================================

// Spec: Application Service API v1.19, "Registration": the `users` namespace matches when "a local user
// matching one of the namespaces is the target of the event". An invite names its target in `state_key`,
// and the invitee is not yet a joined member of the room.
SCENARIO("an appservice is sent an invite to one of its virtual users", "[appservice][integration][delivery][r07]")
{
    GIVEN("an appservice owning @_bridge_* users and a human who has made a room it is not part of")
    {
        auto const bridge = TestAppservice{.id = "bridge", .users_regex = "@_bridge_.*"};
        auto mock = MockAppservice{};
        auto bridge_with_url = bridge;
        bridge_with_url.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge_with_url}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const alice = register_human(runtime, "alice");
        std::ignore = register_human(runtime, "bob");
        register_virtual_user(runtime, bridge_with_url, "_bridge_dave");
        auto const room_id = create_room(runtime, alice);
        clock.drain(runtime);
        REQUIRE(events_received(mock).empty());

        WHEN("the human invites the virtual user")
        {
            auto const invited = call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                                      R"({"user_id":"@_bridge_dave:example.org"})");
            REQUIRE(invited.response.status == 200U);
            clock.drain(runtime);

            THEN("the appservice receives the m.room.member invite, naming its user in state_key")
            {
                auto const seen = events_received(mock);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.room.member");
                CHECK(seen.front().state_key == std::optional<std::string>{"@_bridge_dave:example.org"});
                CHECK(seen.front().membership == "invite");
                CHECK(seen.front().sender == "@alice:example.org");
                CHECK(seen.front().room_id == room_id);
            }
        }

        WHEN("the human invites an ordinary user instead")
        {
            auto const invited = call(runtime, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice,
                                      R"({"user_id":"@bob:example.org"})");
            REQUIRE(invited.response.status == 200U);
            clock.drain(runtime);

            THEN("the appservice is not interested and receives nothing")
            {
                CHECK(events_received(mock).empty());
            }
        }
    }
}

// Spec: Application Service API v1.19, "Registration": the `users` namespace matches when "a local user
// matching one of the namespaces is the target of the event". A remote user's invite to a bridged user
// arrives on PUT /_matrix/federation/v2/invite, usually for a room this server has never been in: there is
// no local room and no transaction carries the event to us later, so the invite handler must queue it.
SCENARIO("an appservice is sent a federated invite to one of its virtual users in a room this server does not know",
         "[appservice][integration][delivery][r07]")
{
    GIVEN("an appservice owning @_bridge_* users and federation callbacks wired")
    {
        auto const bridge = TestAppservice{.id = "bridge", .users_regex = "@_bridge_.*"};
        auto mock = MockAppservice{};
        auto bridge_with_url = bridge;
        bridge_with_url.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge_with_url}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
        REQUIRE(runtime.homeserver.federation.invite_handler);
        auto clock = SteppedClock{};
        std::ignore = register_human(runtime, "bob");
        register_virtual_user(runtime, bridge_with_url, "_bridge_dave");
        clock.drain(runtime);
        REQUIRE(events_received(mock).empty());

        auto const invite_to = [&](std::string const& invitee, std::string const& event_id) {
            auto request = merovingian::federation::InviteRequest{};
            request.room_id = "!remote_room:remote.example.org";
            request.event_id = event_id;
            request.room_version = "12";
            request.origin = "remote.example.org";
            request.invite_event_json =
                R"({"auth_events":[],"content":{"membership":"invite"},"depth":7,"origin_server_ts":1,)"
                R"("prev_events":[],"room_id":"!remote_room:remote.example.org","sender":"@alice:remote.example.org",)"
                R"("state_key":")" +
                invitee + R"(","type":"m.room.member"})";
            return runtime.homeserver.federation.invite_handler(request);
        };

        WHEN("a remote user invites the virtual user")
        {
            auto const accepted = invite_to("@_bridge_dave:example.org", "$invite_dave:remote.example.org");
            REQUIRE(accepted.accepted);
            clock.drain(runtime);

            THEN("the appservice receives the m.room.member invite, naming its user in state_key")
            {
                auto const seen = events_received(mock);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.room.member");
                CHECK(seen.front().state_key == std::optional<std::string>{"@_bridge_dave:example.org"});
                CHECK(seen.front().membership == "invite");
                CHECK(seen.front().sender == "@alice:remote.example.org");
                CHECK(seen.front().room_id == "!remote_room:remote.example.org");
            }
        }

        WHEN("a remote user invites an ordinary local user instead")
        {
            auto const accepted = invite_to("@bob:example.org", "$invite_bob:remote.example.org");
            REQUIRE(accepted.accepted);
            clock.drain(runtime);

            THEN("the appservice is not interested and receives nothing")
            {
                CHECK(events_received(mock).empty());
            }
        }
    }
}

// ===========================================================================
// createRoom queues its own events
// ===========================================================================

// R01 triage note: createRoom stored the create, membership, power-level and join-rule events
// and never queued them, so an appservice interested in the room was told nothing about how it began.
SCENARIO("the events createRoom makes are queued for an interested appservice",
         "[appservice][integration][delivery][create-room]")
{
    GIVEN("an appservice interested in every room")
    {
        auto bridge = TestAppservice{.id = "bridge", .rooms_regex = ".*"};
        auto mock = MockAppservice{};
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const alice = register_human(runtime, "alice");

        WHEN("a user creates a named room with a topic")
        {
            auto const room_id = create_room(runtime, alice, R"({"name":"Cheese","topic":"Tasty"})");
            clock.drain(runtime);

            THEN("the appservice receives each of the room's events, the create event first, each once")
            {
                auto const seen = events_received(mock);
                auto types = std::vector<std::string>{};
                for (auto const& event : seen)
                {
                    CHECK(event.room_id == room_id);
                    types.push_back(event.type);
                }
                REQUIRE_FALSE(types.empty());
                CHECK(types.front() == "m.room.create");
                for (auto const* expected :
                     {"m.room.create", "m.room.member", "m.room.power_levels", "m.room.join_rules",
                      "m.room.history_visibility", "m.room.name", "m.room.topic"})
                {
                    CHECK(std::ranges::count(types, std::string{expected}) == 1);
                }
                auto const member = std::ranges::find_if(seen, [](SeenEvent const& event) {
                    return event.type == "m.room.member";
                });
                REQUIRE(member != seen.end());
                CHECK(member->state_key == std::optional<std::string>{"@alice:example.org"});
                CHECK(member->membership == "join");
            }
        }
    }

    GIVEN("an appservice that owns a room alias namespace and a virtual user namespace")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@_bridge_.*", .aliases_regex = "#_bridge_.*"};
        auto mock = MockAppservice{};
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const alice = register_human(runtime, "alice");
        register_virtual_user(runtime, bridge, "_bridge_dave");

        WHEN("a room is created with an alias in that namespace")
        {
            auto const room_id = create_room(runtime, alice, R"({"room_alias_name":"_bridge_chan"})");
            clock.drain(runtime);

            THEN("the appservice receives the room's events, including those made before the alias existed")
            {
                auto const seen = events_received(mock);
                REQUIRE_FALSE(seen.empty());
                CHECK(seen.front().type == "m.room.create");
                CHECK(std::ranges::all_of(seen, [&room_id](SeenEvent const& event) {
                    return event.room_id == room_id;
                }));
            }
        }

        WHEN("a room is created that invites a virtual user and has no alias in the namespace")
        {
            auto const room_id = create_room(runtime, alice, R"({"invite":["@_bridge_dave:example.org"]})");
            clock.drain(runtime);

            THEN("the appservice receives the invite to its user and nothing else of the room")
            {
                auto const seen = events_received(mock);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.room.member");
                CHECK(seen.front().state_key == std::optional<std::string>{"@_bridge_dave:example.org"});
                CHECK(seen.front().membership == "invite");
                CHECK(seen.front().room_id == room_id);
            }
        }
    }
}

// ===========================================================================
// R08: ephemeral data
// ===========================================================================

// Spec: Application Service API v1.19, "Pushing ephemeral data": "If the receive_ephemeral settings is
// enabled in the registration file, homeservers MUST send ephemeral data that is relevant to the
// application service via the transaction API, using the ephemeral property of the request's body."
SCENARIO("an appservice with receive_ephemeral is sent the typing, receipt and presence data relevant to it",
         "[appservice][integration][delivery][r08]")
{
    GIVEN("two appservices owning @_bridge_* users, one of which wants ephemeral data")
    {
        auto wanting = TestAppservice{.id = "wanting", .users_regex = "@_bridge_.*", .receive_ephemeral = true};
        auto declining = TestAppservice{.id = "declining", .users_regex = "@_bridge_.*"};
        auto wanting_mock = MockAppservice{};
        auto declining_mock = MockAppservice{};
        wanting.url = wanting_mock.url();
        declining.url = declining_mock.url();
        auto config = merovingian::tests::appservice_test_config({wanting, declining});
        // Both claim the same non-exclusive namespace, which is legal; exclusivity is not in play.
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const alice = register_human(runtime, "alice");
        auto const bob = register_human(runtime, "bob");
        register_virtual_user(runtime, wanting, "_bridge_dave");

        // A room shared by alice and the virtual user, and a room alice shares only with bob.
        auto const shared_room = create_room(runtime, alice, R"({"preset":"public_chat"})");
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + shared_room + "?user_id=@_bridge_dave:example.org",
                     wanting.as_token(), "{}")
                    .response.status == 200U);
        auto const plain_room = create_room(runtime, alice, R"({"preset":"public_chat"})");
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + plain_room, bob, "{}").response.status == 200U);
        auto const shared_event = send_message(runtime, alice, shared_room, "hello");
        auto const plain_event = send_message(runtime, alice, plain_room, "hello");
        clock.drain(runtime);
        auto const baseline_wanting = transaction_count(wanting_mock);
        auto const baseline_declining = transaction_count(declining_mock);

        WHEN("typing starts in the shared room and in the room without a virtual user")
        {
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + shared_room + "/typing/@alice:example.org",
                         alice, R"({"typing":true,"timeout":30000})")
                        .response.status == 200U);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + plain_room + "/typing/@alice:example.org", alice,
                         R"({"typing":true,"timeout":30000})")
                        .response.status == 200U);
            clock.drain(runtime);

            THEN("only the shared room's typing reaches the appservice that wants it, with the room_id")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.typing");
                CHECK(seen.front().room_id == shared_room);
                CHECK(seen.front().raw_content == R"({"user_ids":["@alice:example.org"]})");
            }

            THEN("the appservice that did not set receive_ephemeral receives no ephemeral data and no transaction")
            {
                CHECK(ephemeral_received(declining_mock, baseline_declining).empty());
                CHECK(transaction_count(declining_mock) == baseline_declining);
            }
        }

        WHEN("a read receipt is sent in the shared room")
        {
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + shared_room + "/receipt/m.read/" + shared_event,
                         alice, "{}")
                        .response.status == 200U);
            clock.drain(runtime);

            THEN("it reaches the appservice as an m.receipt with the room_id")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.receipt");
                CHECK(seen.front().room_id == shared_room);
                CHECK(seen.front().raw_content.find(shared_event) != std::string::npos);
                CHECK(seen.front().raw_content.find("@alice:example.org") != std::string::npos);
            }
        }

        WHEN("a read receipt is sent in the room the appservice has no stake in")
        {
            REQUIRE(call(runtime, "POST", "/_matrix/client/v3/rooms/" + plain_room + "/receipt/m.read/" + plain_event,
                         alice, "{}")
                        .response.status == 200U);
            clock.drain(runtime);

            THEN("nothing is sent")
            {
                CHECK(ephemeral_received(wanting_mock, baseline_wanting).empty());
            }
        }

        WHEN("a human's private read receipt and the virtual user's private read receipt are sent in the shared room")
        {
            REQUIRE(call(runtime, "POST",
                         "/_matrix/client/v3/rooms/" + shared_room + "/receipt/m.read.private/" + shared_event, alice,
                         "{}")
                        .response.status == 200U);
            REQUIRE(call(runtime, "POST",
                         "/_matrix/client/v3/rooms/" + shared_room + "/receipt/m.read.private/" + shared_event +
                             "?user_id=@_bridge_dave:example.org",
                         wanting.as_token(), "{}")
                        .response.status == 200U);
            clock.drain(runtime);

            THEN("only the private receipt of a user in the appservice's namespaces is sent")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.receipt");
                CHECK(seen.front().raw_content.find("@_bridge_dave:example.org") != std::string::npos);
                CHECK(seen.front().raw_content.find("@alice:example.org") == std::string::npos);
            }
        }

        WHEN("a user who shares a room with the virtual user changes presence, and one who does not does too")
        {
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/presence/@alice:example.org/status", alice,
                         R"({"presence":"online","status_msg":"here"})")
                        .response.status == 200U);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/presence/@bob:example.org/status", bob,
                         R"({"presence":"unavailable"})")
                        .response.status == 200U);
            clock.drain(runtime);

            THEN("only the sharing user's presence reaches the appservice, as m.presence from that sender")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.presence");
                CHECK(seen.front().sender == "@alice:example.org");
                CHECK(seen.front().room_id.empty());
                CHECK(seen.front().raw_content.find(R"("presence":"online")") != std::string::npos);
            }
        }

        WHEN("the sharing user's presence changes on a server whose other rooms hold more members than the "
             "presence budget")
        {
            // Rooms the subject is not in. Finding the rooms a user is in must not spend the budget meant
            // for the namespace checks, or a busy server would stop sending presence for shared rooms.
            auto const crowd_room_count = std::size_t{4U};
            auto const crowd_size = merovingian::homeserver::max_appservice_presence_member_checks / 2U;
            for (auto index = std::size_t{0U}; index < crowd_room_count; ++index)
            {
                auto crowd = merovingian::homeserver::LocalRoom{};
                crowd.room_id = "!crowd" + std::to_string(index) + ":example.org";
                for (auto member = std::size_t{0U}; member < crowd_size; ++member)
                {
                    crowd.members.push_back("@crowd" + std::to_string(index) + "_" + std::to_string(member) +
                                            ":example.org");
                }
                runtime.homeserver.database.rooms.push_back(std::move(crowd));
            }
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/presence/@alice:example.org/status", alice,
                         R"({"presence":"online"})")
                        .response.status == 200U);
            clock.drain(runtime);

            THEN("the presence still reaches the appservice that shares a room with the user")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.presence");
                CHECK(seen.front().sender == "@alice:example.org");
            }
        }

        WHEN("a user who shares a room with the virtual user changes their display name")
        {
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/profile/@alice:example.org/displayname", alice,
                         R"({"displayname":"Alice Renamed"})")
                        .response.status == 200U);
            clock.drain(runtime);

            THEN("the m.presence the profile change sends reaches the appservice with the new display name")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                auto const presence = std::ranges::find_if(seen, [](SeenEphemeral const& item) {
                    return item.type == "m.presence";
                });
                REQUIRE(presence != seen.end());
                CHECK(presence->sender == "@alice:example.org");
                CHECK(presence->raw_content.find(R"("displayname":"Alice Renamed")") != std::string::npos);
            }
        }

        WHEN("the virtual user's own presence changes")
        {
            REQUIRE(
                call(runtime, "PUT",
                     "/_matrix/client/v3/presence/@_bridge_dave:example.org/status?user_id=@_bridge_dave:example.org",
                     wanting.as_token(), R"({"presence":"online"})")
                    .response.status == 200U);
            clock.drain(runtime);

            THEN("it matches the appservice's namespaces and is sent")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().type == "m.presence");
                CHECK(seen.front().sender == "@_bridge_dave:example.org");
            }
        }

        WHEN("the same room's typing changes several times before the appservice is next reached")
        {
            for (auto const* typing : {"true", "false", "true"})
            {
                REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + shared_room + "/typing/@alice:example.org",
                             alice, std::string{R"({"typing":)"} + typing + R"(,"timeout":30000})")
                            .response.status == 200U);
            }
            clock.drain(runtime);

            THEN("one m.typing carries the latest state rather than a history of stale ones")
            {
                auto const seen = ephemeral_received(wanting_mock, baseline_wanting);
                REQUIRE(seen.size() == 1U);
                CHECK(seen.front().raw_content == R"({"user_ids":["@alice:example.org"]})");
            }
        }
    }
}

// Spec: "Homeservers MUST NOT alter (e.g. add more) events they were going to send within that
// transaction ID on retries." A transaction that carried ephemeral data is retried with the same
// data; whatever arrived since goes in a later transaction.
SCENARIO("a failed ephemeral transaction is retried under the same id with the same items",
         "[appservice][integration][delivery][r08]")
{
    GIVEN("an appservice that wants ephemeral data and is briefly down")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@_bridge_.*", .receive_ephemeral = true};
        auto mock = MockAppservice{};
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const alice = register_human(runtime, "alice");
        register_virtual_user(runtime, bridge, "_bridge_dave");
        auto const room_id = create_room(runtime, alice, R"({"preset":"public_chat"})");
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_id + "?user_id=@_bridge_dave:example.org",
                     bridge.as_token(), "{}")
                    .response.status == 200U);
        clock.drain(runtime);
        auto const baseline = mock.requests_to("/_matrix/app/v1/transactions/").size();
        mock.set_status(503);

        WHEN("typing is queued, the send fails, more ephemeral data arrives, and the appservice comes back")
        {
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/typing/@alice:example.org", alice,
                         R"({"typing":true,"timeout":30000})")
                        .response.status == 200U);
            clock.drain(runtime);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/presence/@alice:example.org/status", alice,
                         R"({"presence":"online"})")
                        .response.status == 200U);
            mock.set_status(200);
            clock.drain(runtime);
            clock.drain(runtime);
            auto const all = mock.requests_to("/_matrix/app/v1/transactions/");

            THEN("the retry carries the first attempt's id and body exactly, and the presence goes in a later one")
            {
                REQUIRE(all.size() >= baseline + 3U);
                auto const& failed = all[baseline];
                auto const& retried = all[baseline + 1U];
                CHECK(failed.answered_status == 503U);
                CHECK(retried.answered_status == 200U);
                CHECK(failed.target == retried.target);
                CHECK(failed.body == retried.body);
                CHECK(failed.body.find("m.typing") != std::string::npos);
                CHECK(failed.body.find("m.presence") == std::string::npos);
                auto const& later = all[baseline + 2U];
                CHECK(later.target != retried.target);
                CHECK(later.body.find("m.presence") != std::string::npos);
                CHECK(later.body.find("m.typing") == std::string::npos);
            }
        }
    }
}

// Spec: "Homeservers MUST NOT alter (e.g. add more) events they were going to send within that
// transaction ID on retries." When the appservice acknowledged a transaction but the acknowledgement
// did not reach the database, the cursor still names that transaction and the next pass resends it.
// It must carry the ephemeral items it carried the first time, not whatever is queued by then.
SCENARIO("an acknowledged event transaction whose acknowledgement failed to commit is resent unchanged",
         "[appservice][integration][delivery][r08]")
{
    GIVEN("an appservice that wants ephemeral data, an event and a typing item queued for it")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@_bridge_.*", .receive_ephemeral = true};
        auto mock = MockAppservice{};
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const alice = register_human(runtime, "alice");
        register_virtual_user(runtime, bridge, "_bridge_dave");
        auto const room_id = create_room(runtime, alice, R"({"preset":"public_chat"})");
        REQUIRE(call(runtime, "POST", "/_matrix/client/v3/join/" + room_id + "?user_id=@_bridge_dave:example.org",
                     bridge.as_token(), "{}")
                    .response.status == 200U);
        clock.drain(runtime);
        auto const baseline = mock.requests_to("/_matrix/app/v1/transactions/").size();
        REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/typing/@alice:example.org", alice,
                     R"({"typing":true,"timeout":30000})")
                    .response.status == 200U);
        std::ignore = send_message(runtime, alice, room_id, "hello");

        WHEN("the appservice answers 200 but recording the delivery fails, and presence is queued before the "
             "retry")
        {
            merovingian::database::force_persist_failure_for_statement(runtime.homeserver.database.persistent_store,
                                                                       "complete_appservice_outbox_entry");
            clock.drain(runtime);
            REQUIRE(call(runtime, "PUT", "/_matrix/client/v3/presence/@alice:example.org/status", alice,
                         R"({"presence":"online"})")
                        .response.status == 200U);
            clock.drain(runtime);
            clock.drain(runtime);
            auto const all = mock.requests_to("/_matrix/app/v1/transactions/");

            THEN("the resend has the first attempt's id and body, and the presence goes in a later transaction")
            {
                REQUIRE(all.size() >= baseline + 2U);
                auto const& acknowledged = all[baseline];
                auto const& resent = all[baseline + 1U];
                CHECK(acknowledged.answered_status == 200U);
                CHECK(acknowledged.target == resent.target);
                CHECK(acknowledged.body == resent.body);
                CHECK(acknowledged.body.find("m.typing") != std::string::npos);
                CHECK(resent.body.find("m.presence") == std::string::npos);
                REQUIRE(all.size() >= baseline + 3U);
                auto const presence_later = std::ranges::any_of(
                    all.begin() + static_cast<std::ptrdiff_t>(baseline) + 2, all.end(), [](auto const& request) {
                        return request.body.find("m.presence") != std::string::npos;
                    });
                CHECK(presence_later);
            }
        }
    }
}

// ===========================================================================
// ADR-0191: the outbox of an appservice that never returns is capped
// ===========================================================================

SCENARIO("an appservice's queue stops growing at appservice.max_queued_events and says so",
         "[appservice][integration][delivery][r01][adr-0191]")
{
    GIVEN("an appservice interested in every room that is down, and a cap of three events")
    {
        auto bridge = TestAppservice{.id = "bridge", .rooms_regex = ".*"};
        auto mock = MockAppservice{};
        mock.set_status(503);
        bridge.url = mock.url();
        auto config = merovingian::tests::appservice_test_config({bridge});
        config.appservice().max_queued_events = 3U;
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto clock = SteppedClock{};
        auto const alice = register_human(runtime, "alice");

        WHEN("more events than the cap are produced while it is down")
        {
            auto const room_id = create_room(runtime, alice);
            for (auto index = 0; index < 5; ++index)
            {
                std::ignore = send_message(runtime, alice, room_id, "message" + std::to_string(index));
            }
            auto const& store = runtime.homeserver.database.persistent_store;

            THEN("exactly the cap is queued, and they are the oldest events")
            {
                CHECK(merovingian::database::count_appservice_outbox_entries(store, "bridge") == 3U);
                auto queued_types = std::vector<std::string>{};
                for (auto const& entry : store.appservice_outbox)
                {
                    auto const event = std::ranges::find_if(store.events, [&entry](auto const& candidate) {
                        return candidate.event_id == entry.event_id;
                    });
                    REQUIRE(event != store.events.end());
                    auto const parsed = merovingian::tests::parse_object(event->json);
                    queued_types.push_back(*merovingian::tests::string_member(parsed, "type"));
                }
                CHECK(queued_types ==
                      std::vector<std::string>{"m.room.create", "m.room.member", "m.room.power_levels"});
            }

            THEN("every event that was not queued is counted")
            {
                auto const dropped = runtime.homeserver.appservice_outbox_dropped.find("bridge");
                REQUIRE(dropped != runtime.homeserver.appservice_outbox_dropped.end());
                CHECK(dropped->second >= 5U);
            }

            THEN("the first refusal was audited, naming the appservice")
            {
                auto const audited = std::ranges::any_of(store.audit_log, [](auto const& row) {
                    return row.event_type == "appservice.outbox.full" && row.actor == "bridge";
                });
                CHECK(audited);
            }

            THEN("the drop count and the queue depth are exposed as metrics")
            {
                auto const metrics = merovingian::homeserver::admin_metrics_summary(runtime.homeserver);
                CHECK(metrics.find("merovingian_appservice_outbox_dropped_total") != std::string::npos);
                CHECK(metrics.find("merovingian_appservice_outbox_queued") != std::string::npos);
                CHECK(metrics.find("bridge") != std::string::npos);
            }

            AND_WHEN("the appservice comes back")
            {
                mock.set_status(200);
                clock.drain(runtime);

                THEN("the queued events are delivered oldest first and the queue empties")
                {
                    auto types = std::vector<std::string>{};
                    for (auto const& event : events_received(mock))
                    {
                        types.push_back(event.type);
                    }
                    // The failed 503 attempts recorded the same first event; the successful run delivers 3.
                    REQUIRE(types.size() >= 3U);
                    CHECK(types.back() == "m.room.power_levels");
                    CHECK(merovingian::database::count_appservice_outbox_entries(store, "bridge") == 0U);
                }
            }
        }
    }
}

// ===========================================================================
// ADR-0192: an appservice's network directory is durable
// ===========================================================================

SCENARIO("a room an appservice published to its network directory is still listed after a restart",
         "[appservice][integration][directory][adr-0192][restart]")
{
    GIVEN("a SQLite-backed homeserver in which an appservice has published a room to its irc network")
    {
        auto bridge = TestAppservice{.id = "bridge", .rooms_regex = ".*", .protocols = {"irc"}};
        auto mock = MockAppservice{};
        mock.set_answer("/_matrix/app/v1/thirdparty/protocol/irc", 200U,
                        R"({"field_types":{},"icon":"mxc://example.org/i","instances":[{"desc":"d","fields":{},)"
                        R"("network_id":"freenode"}],"location_fields":[],"user_fields":[]})");
        bridge.url = mock.url();
        auto config = merovingian::tests::appservice_test_config({bridge});
        auto const sqlite_path =
            merovingian::tests::temporary_directory() /
            ("merovingian-as-directory-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
             ".sqlite3");
        config.database().backend = merovingian::config::DatabaseBackend::sqlite;
        config.database().uri_file.clear();
        config.database().sqlite_path = sqlite_path.string();
        auto room_id = std::string{};
        auto instance_id = std::string{};
        {
            auto first = merovingian::homeserver::start_client_server(config);
            REQUIRE(first.started);
            auto const alice = register_human(first.runtime, "alice");
            room_id = create_room(first.runtime, alice);
            auto const listed =
                call(first.runtime, "PUT", "/_matrix/client/v3/directory/list/appservice/irc/" + room_id,
                     bridge.as_token(), R"({"visibility":"public"})");
            REQUIRE(listed.response.status == 200U);
            auto const protocol = call(first.runtime, "GET", "/_matrix/client/v3/thirdparty/protocol/irc", alice);
            REQUIRE(protocol.response.status == 200U);
            auto const body = merovingian::tests::parse_object(protocol.response.body);
            auto const* instances = merovingian::tests::object_member_as_array(body, "instances");
            REQUIRE(instances != nullptr);
            REQUIRE_FALSE(instances->empty());
            instance_id = *merovingian::tests::string_member(
                *std::get_if<merovingian::canonicaljson::Object>(&instances->front().storage()), "instance_id");
        }

        WHEN("the server restarts")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto const alice = [&]() {
                auto const login =
                    call(restarted.runtime, "POST", "/_matrix/client/v3/login", {},
                         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                         R"("password":"CorrectHorse7!"})");
                REQUIRE(login.response.status == 200U);
                return string_in(login.response.body, "access_token");
            }();
            auto const listing = call(restarted.runtime, "POST", "/_matrix/client/v3/publicRooms", alice,
                                      R"({"third_party_instance_id":")" + instance_id + R"("})");

            THEN("the network's directory still lists the room")
            {
                REQUIRE(listing.response.status == 200U);
                auto const body = merovingian::tests::parse_object(listing.response.body);
                auto const* chunk = merovingian::tests::object_member_as_array(body, "chunk");
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 1U);
                CHECK(*merovingian::tests::string_member(
                          *std::get_if<merovingian::canonicaljson::Object>(&chunk->front().storage()), "room_id") ==
                      room_id);
                CHECK(merovingian::database::appservice_directory_contains(
                    restarted.runtime.homeserver.database.persistent_store, "bridge", "irc", room_id));
            }
        }
        std::filesystem::remove(sqlite_path);
    }
}

// Project policy (ADR-0192), not the spec: PUT /directory/list/appservice/{networkId}/{roomId} documents no
// failure status beyond refusing callers that are not appservices, so these fail-closed refusals live here
// rather than in the conformance suite. An appservice lists only under a protocol it declares, only a room
// that exists, and only a room it is interested in, so it cannot put an arbitrary private room's metadata
// in a public directory.
SCENARIO("an appservice may list only a room it is interested in, under a protocol it declares",
         "[appservice][integration][directory][adr-0192][security]")
{
    GIVEN("one appservice interested only in rooms containing its users, another declaring slack, and a room")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@_bridge_.*", .protocols = {"irc"}};
        auto other = TestAppservice{.id = "other", .rooms_regex = ".*", .protocols = {"slack"}};
        auto mock = MockAppservice{};
        auto other_mock = MockAppservice{};
        bridge.url = mock.url();
        other.url = other_mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge, other}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_human(runtime, "alice");
        auto const room_id = create_room(runtime, alice);
        auto const errcode_of = [](merovingian::homeserver::DispatchResult const& result) {
            return string_in(result.response.body, "errcode");
        };

        WHEN("the appservice names a protocol it does not declare")
        {
            auto const result = call(runtime, "PUT", "/_matrix/client/v3/directory/list/appservice/slack/" + room_id,
                                     bridge.as_token(), R"({"visibility":"public"})");

            THEN("404 M_NOT_FOUND: another appservice's protocol is not its to list under")
            {
                CHECK(result.response.status == 404U);
                CHECK(errcode_of(result) == "M_NOT_FOUND");
            }
        }

        WHEN("the appservice names a room that does not exist")
        {
            auto const result =
                call(runtime, "PUT", "/_matrix/client/v3/directory/list/appservice/irc/%21missing%3Aexample.org",
                     bridge.as_token(), R"({"visibility":"public"})");

            THEN("404 M_NOT_FOUND")
            {
                CHECK(result.response.status == 404U);
                CHECK(errcode_of(result) == "M_NOT_FOUND");
            }
        }

        WHEN("the appservice names a room it has no interest in")
        {
            auto const result = call(runtime, "PUT", "/_matrix/client/v3/directory/list/appservice/irc/" + room_id,
                                     bridge.as_token(), R"({"visibility":"public"})");

            THEN("403 M_FORBIDDEN, and no network directory lists the room")
            {
                CHECK(result.response.status == 403U);
                CHECK(errcode_of(result) == "M_FORBIDDEN");
                CHECK_FALSE(merovingian::database::appservice_directory_contains(
                    runtime.homeserver.database.persistent_store, "bridge", "irc", room_id));
                auto const listing =
                    call(runtime, "POST", "/_matrix/client/v3/publicRooms", alice, R"({"include_all_networks":true})");
                REQUIRE(listing.response.status == 200U);
                CHECK(listing.response.body.find(room_id) == std::string::npos);
            }
        }
    }
}

// ===========================================================================
// sp02.thirdparty-no-proxy-slot
// ===========================================================================

// ADR-0079: a request that makes this server call out before it can answer holds a request-pool
// thread for the round trip, so it first takes a slot in the client-outbound budget. The bare
// /thirdparty/location and /thirdparty/user routes fan out to EVERY registration, sequentially,
// each for up to the appservice timeout, and took none.
SCENARIO("the bare third-party lookups run under the client-outbound budget",
         "[appservice][integration][thirdparty][security][sp02]")
{
    GIVEN("an appservice that never answers, and a budget of one call per client")
    {
        auto bridge = TestAppservice{.id = "bridge", .protocols = {"irc"}};
        auto mock = MockAppservice{};
        mock.go_silent(true);
        bridge.url = mock.url();
        auto config = merovingian::tests::appservice_test_config({bridge});
        config.appservice().connect_timeout_seconds = 1U;
        config.appservice().total_timeout_seconds = 2U;
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_human(runtime, "alice");

        auto const routes = std::vector<std::string>{
            "/_matrix/client/v3/thirdparty/location?alias=%23chan%3Aexample.org",
            "/_matrix/client/v3/thirdparty/user?userid=%40someone%3Aexample.org",
            "/_matrix/client/v3/thirdparty/location/irc",
            "/_matrix/client/v3/thirdparty/user/irc",
            "/_matrix/client/v3/thirdparty/protocols",
            "/_matrix/client/v3/thirdparty/protocol/irc",
        };

        for (auto const& route : routes)
        {
            WHEN("one lookup holds the client's only slot and the same client asks " + route)
            {
                auto holder = merovingian::homeserver::DispatchResult{};
                auto second = merovingian::homeserver::DispatchResult{};
                auto held = false;
                {
                    auto threads = merovingian::tests::JoiningThreads{};
                    threads.emplace_back([&]() {
                        holder = call(runtime, "GET", routes.front(), alice, {}, "192.0.2.10");
                    });
                    auto const deadline = std::chrono::steady_clock::now() + 3s;
                    while (std::chrono::steady_clock::now() < deadline && !held)
                    {
                        held = runtime.homeserver.client_outbound_budget->active() == 1U;
                        std::this_thread::sleep_for(5ms);
                    }
                    second = call(runtime, "GET", route, alice, {}, "192.0.2.10");
                }

                THEN("the second is refused with 429 M_LIMIT_EXCEEDED before any outbound call")
                {
                    REQUIRE(held);
                    CHECK(second.response.status == 429U);
                    auto const body = merovingian::tests::parse_object(second.response.body);
                    auto const* errcode = merovingian::tests::string_member(body, "errcode");
                    REQUIRE(errcode != nullptr);
                    CHECK(*errcode == "M_LIMIT_EXCEEDED");
                    // Only the holder's single call ever reached the appservice.
                    CHECK(mock.requests().size() <= 1U);
                }

                THEN("the slot is returned once the holder's call ends")
                {
                    CHECK(runtime.homeserver.client_outbound_budget->active() == 0U);
                    CHECK(holder.response.status == 404U);
                }
            }
        }

        WHEN("the lookup is made with no slot taken")
        {
            auto const answered =
                call(runtime, "GET", "/_matrix/client/v3/thirdparty/protocols", alice, {}, "192.0.2.11");

            THEN("it is served normally: the slot is a cap, not a gate on every call")
            {
                CHECK(answered.response.status == 200U);
                CHECK(runtime.homeserver.client_outbound_budget->active() == 0U);
            }
        }
    }
}
