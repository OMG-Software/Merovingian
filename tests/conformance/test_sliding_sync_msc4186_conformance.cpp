// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |      MSC4186 SIMPLIFIED SLIDING SYNC: REQUEST-LEVEL CONFORMANCE        |
// |                                                                         |
// |  Spec: MSC4186 Simplified Sliding Sync, as merged on 2026-06-29         |
// |  URL:  https://github.com/matrix-org/matrix-spec-proposals/blob/main/   |
// |          proposals/4186-simplified-sliding-sync.md                       |
// |  and its extension MSCs: MSC4508 (typing, common extension semantics),  |
// |  MSC4538 (to_device), MSC4543 (e2ee), MSC4548 (account_data),           |
// |  MSC4551 (receipts).                                                    |
// |                                                                         |
// |  Every REQUIRE marked "Spec MUST" encodes a MUST of those texts. If one |
// |  fails, fix the IMPLEMENTATION. Do not weaken, remove or re-value an    |
// |  assertion without citing the proposal. Deviations are ADR-0865 and    |
// |  ADR-0868, and are not asserted here.                                  |
// +-------------------------------------------------------------------------+

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
namespace json = merovingian::canonicaljson;
using merovingian::tests::int_member;
using merovingian::tests::object_member;
using merovingian::tests::object_member_as_array;
using merovingian::tests::object_member_as_object;
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

constexpr auto sync_path = std::string_view{"/_matrix/client/unstable/org.matrix.msc4186/sync"};
constexpr auto password = std::string_view{"CorrectHorse7!"};

// One list, `all`, holding every room, with a one-event timeline.
constexpr auto list_body = std::string_view{
    R"({"lists":{"all":{"ranges":[[0,99]],"required_state":[["m.room.name",""]],"timeline_limit":1}}})"};

[[nodiscard]] auto call(hs::ClientServerRuntime& rt, std::string const& token, std::string const& method,
                        std::string const& target, std::string const& body) -> hs::DispatchResult
{
    return hs::handle_client_server_request(rt, {method, target, token, body}, /*can_wait=*/false);
}

[[nodiscard]] auto register_user(hs::ClientServerRuntime& rt, std::string_view localpart) -> std::string
{
    auto const registered =
        call(rt, {}, "POST", "/_matrix/client/v3/register", merovingian::tests::registration_json(localpart, password));
    REQUIRE(registered.response.status == 200U);
    return merovingian::tests::access_token_from(registered.response.body);
}

// A second device of an existing account.
[[nodiscard]] auto login_device(hs::ClientServerRuntime& rt, std::string_view localpart, std::string_view device)
    -> std::string
{
    auto const logged_in =
        call(rt, {}, "POST", "/_matrix/client/v3/login",
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + std::string{localpart} +
                 R"("},"password":")" + std::string{password} + R"(","device_id":")" + std::string{device} + R"("})");
    REQUIRE(logged_in.response.status == 200U);
    return merovingian::tests::access_token_from(logged_in.response.body);
}

auto expect_ok(hs::ClientServerRuntime& rt, std::string const& token, std::string const& method,
               std::string const& target, std::string const& body) -> void
{
    REQUIRE(call(rt, token, method, target, body).response.status == 200U);
}

[[nodiscard]] auto make_room(hs::ClientServerRuntime& rt, std::string const& token, std::string const& body)
    -> std::string
{
    auto const created = call(rt, token, "POST", "/_matrix/client/v3/createRoom", body);
    REQUIRE(created.response.status == 200U);
    return merovingian::tests::string_field(created.response.body, "room_id");
}

auto send_text(hs::ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
               std::string const& txn) -> void
{
    expect_ok(rt, token, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn,
              R"({"msgtype":"m.text","body":")" + txn + R"("})");
}

[[nodiscard]] auto sliding(hs::ClientServerRuntime& rt, std::string const& token, std::string_view body,
                           std::string const& pos = {}, std::string const& query = {}, bool can_wait = false)
    -> hs::DispatchResult
{
    auto target = std::string{sync_path};
    auto separator = '?';
    if (!pos.empty())
    {
        target += "?pos=" + pos;
        separator = '&';
    }
    if (!query.empty())
    {
        target += separator + query;
    }
    return hs::handle_client_server_request(rt, {"POST", target, token, std::string{body}}, can_wait);
}

[[nodiscard]] auto pos_of(hs::DispatchResult const& result) -> std::string
{
    REQUIRE(result.status == hs::DispatchResult::Status::complete);
    REQUIRE(result.response.status == 200U);
    auto const body = parse_object(result.response.body);
    auto const* pos = string_member(body, "pos");
    REQUIRE(pos != nullptr);
    return pos == nullptr ? std::string{} : *pos;
}

// The response's entry for `room_id`; `present` is false when it has none.
struct RoomEntry final
{
    bool present{false};
    json::Object value{};
};

[[nodiscard]] auto room_entry(std::string const& response_body, std::string const& room_id) -> RoomEntry
{
    auto const body = parse_object(response_body);
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* room = rooms == nullptr ? nullptr : object_member_as_object(*rooms, room_id);
    return room == nullptr ? RoomEntry{} : RoomEntry{true, *room};
}

[[nodiscard]] auto membership_of(RoomEntry const& entry) -> std::string
{
    auto const* membership = string_member(entry.value, "membership");
    return membership == nullptr ? std::string{} : *membership;
}

[[nodiscard]] auto errcode_of(hs::DispatchResult const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

// The (type, state_key) of each event of a room's `required_state`, sorted.
[[nodiscard]] auto required_state_keys(RoomEntry const& entry) -> std::vector<std::pair<std::string, std::string>>
{
    auto keys = std::vector<std::pair<std::string, std::string>>{};
    auto const* state = object_member_as_array(entry.value, "required_state");
    if (state == nullptr)
    {
        return keys;
    }
    for (auto const& event : *state)
    {
        auto const& object = std::get<json::Object>(event.storage());
        auto const* type = string_member(object, "type");
        auto const* state_key = string_member(object, "state_key");
        keys.emplace_back(type == nullptr ? std::string{} : *type, state_key == nullptr ? std::string{} : *state_key);
    }
    std::ranges::sort(keys);
    return keys;
}

// Whether `keys` holds an event of `type`.
// The `content.membership` of each event in a room entry's timeline, in order.
[[nodiscard]] auto timeline_memberships(RoomEntry const& entry) -> std::vector<std::string>
{
    auto memberships = std::vector<std::string>{};
    auto const* timeline = object_member_as_array(entry.value, "timeline");
    REQUIRE(timeline != nullptr);
    for (auto const& event : *timeline)
    {
        auto const* content = object_member_as_object(std::get<json::Object>(event.storage()), "content");
        REQUIRE(content != nullptr);
        auto const* membership = string_member(*content, "membership");
        REQUIRE(membership != nullptr);
        memberships.push_back(*membership);
    }
    return memberships;
}

[[nodiscard]] auto holds_type(std::vector<std::pair<std::string, std::string>> const& keys, std::string_view type)
    -> bool
{
    return std::ranges::any_of(keys, [type](auto const& key) {
        return key.first == type;
    });
}

// The `type` of each event of a room's timeline, in order.
[[nodiscard]] auto timeline_types(RoomEntry const& entry) -> std::vector<std::string>
{
    auto types = std::vector<std::string>{};
    auto const* timeline = object_member_as_array(entry.value, "timeline");
    if (timeline == nullptr)
    {
        return types;
    }
    for (auto const& event : *timeline)
    {
        auto const* type = string_member(std::get<json::Object>(event.storage()), "type");
        types.push_back(type == nullptr ? std::string{} : *type);
    }
    return types;
}

[[nodiscard]] auto start_server() -> hs::ClientServerStartResult
{
    return hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
}

} // namespace

// Spec: MSC4186 — "Connections"
// URL: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// "Servers MUST reject a `pos` that was not issued to the requesting user and device, responding with
// `M_UNKNOWN_POS`."
SCENARIO("MSC4186 a pos is refused to any user or device it was not issued to",
         "[sync][sliding-sync][conformance][msc4186][pos][security]")
{
    GIVEN("a pos issued to alice's first device")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const alice_second = login_device(rt, "alice", "SECONDDEVICE");
        auto const bob = register_user(rt, "bob");
        auto const pos = pos_of(sliding(rt, alice, list_body));

        WHEN("bob, alice's second device and alice's first device each send it")
        {
            auto const by_bob = sliding(rt, bob, list_body, pos);
            auto const by_second = sliding(rt, alice_second, list_body, pos);
            auto const by_owner = sliding(rt, alice, list_body, pos);

            THEN("only the device it was issued to is answered")
            {
                // Spec MUST: a pos not issued to the requesting user is rejected with M_UNKNOWN_POS.
                REQUIRE(by_bob.response.status == 400U);
                // Spec MUST: the refusal's errcode is M_UNKNOWN_POS.
                REQUIRE(errcode_of(by_bob) == "M_UNKNOWN_POS");
                // Spec MUST: a pos not issued to the requesting device is rejected with M_UNKNOWN_POS.
                REQUIRE(by_second.response.status == 400U);
                // Spec MUST: the refusal's errcode is M_UNKNOWN_POS.
                REQUIRE(errcode_of(by_second) == "M_UNKNOWN_POS");
                // Spec MUST: the user and device a pos was issued to continue the connection with it.
                REQUIRE(by_owner.response.status == 200U);
            }
        }

        WHEN("alice sends it with one character changed")
        {
            auto altered = pos;
            altered.back() = altered.back() == '0' ? '1' : '0';
            auto const result = sliding(rt, alice, list_body, altered);

            THEN("it is refused as a pos this server did not issue")
            {
                // Spec MUST: a pos the server did not issue is rejected with M_UNKNOWN_POS.
                REQUIRE(result.response.status == 400U);
                // Spec MUST: the refusal's errcode is M_UNKNOWN_POS.
                REQUIRE(errcode_of(result) == "M_UNKNOWN_POS");
            }
        }
    }
}

// Spec: MSC4186 — "Connections"
//
// "A `pos` token can be used in `/messages` and `/relations` APIs, in the same way as a `next_batch` from `/v3/sync`."
SCENARIO("MSC4186 a pos is accepted as a /messages token", "[sync][sliding-sync][conformance][msc4186][pos]")
{
    GIVEN("alice's room with a message, and a pos issued after it")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room_id = make_room(rt, alice, "{}");
        send_text(rt, alice, room_id, "first");
        auto const pos = pos_of(sliding(rt, alice, list_body));

        WHEN("alice pages back from the pos with /messages")
        {
            auto const messages = call(
                rt, alice, "GET", "/_matrix/client/v3/rooms/" + room_id + "/messages?dir=b&limit=10&from=" + pos, {});

            THEN("the pos is read as a position and the message is returned")
            {
                // Spec MUST (MSC4186 "Connections"): a pos is usable in /messages as a /v3/sync next_batch is.
                REQUIRE(messages.response.status == 200U);
                // Spec MUST: /messages from the pos returns the events before it, as from a next_batch.
                REQUIRE(messages.response.body.find("\"first\"") != std::string::npos);
            }
        }
    }
}

// Spec: MSC4186 — "Request body", `timeout`: "Ignored when no `pos` is set."
SCENARIO("MSC4186 a request without a pos is answered at once, whatever its timeout",
         "[sync][sliding-sync][conformance][msc4186]")
{
    GIVEN("a user with nothing new to sync")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");

        WHEN("she sends a request with a 30 second timeout and no pos, on a connection that may wait")
        {
            auto const result = sliding(rt, alice, list_body, {}, "timeout=30000", /*can_wait=*/true);

            THEN("it is answered, not parked")
            {
                // Spec MUST: `timeout` is ignored without a pos.
                REQUIRE(result.status == hs::DispatchResult::Status::complete);
                // Spec MUST: the request is answered as a normal response, at once.
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}

// Spec: MSC4186 — "Room result": `membership`, `bump_stamp`, `lists`, `heroes` ("only if the room has no name").
SCENARIO("MSC4186 a joined room carries its membership, bump stamp, lists and heroes",
         "[sync][sliding-sync][conformance][msc4186][room-result]")
{
    GIVEN("alice and bob in an unnamed room, and a named room of alice's alone")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const unnamed = make_room(rt, alice, R"({"invite":["@bob:example.org"]})");
        expect_ok(rt, bob, "POST", "/_matrix/client/v3/rooms/" + unnamed + "/join", "{}");
        send_text(rt, alice, unnamed, "hello");
        auto const named = make_room(rt, alice, R"({"name":"Named"})");

        WHEN("alice syncs one list and subscribes to the named room")
        {
            auto const body =
                std::string{R"({"lists":{"all":{"ranges":[[0,99]],"required_state":[],"timeline_limit":1}},)"} +
                R"("room_subscriptions":{")" + named + R"(":{"required_state":[],"timeline_limit":1}}})";
            auto const result = sliding(rt, alice, body);
            REQUIRE(result.response.status == 200U);
            auto const unnamed_entry = room_entry(result.response.body, unnamed);
            auto const named_entry = room_entry(result.response.body, named);

            THEN("each room says she is joined, gives a bump stamp and names the list that holds it")
            {
                // Spec MUST: a room in a list's range is sent on the connection's first response.
                REQUIRE(unnamed_entry.present);
                // Spec MUST: a room in a list's range is sent on the connection's first response.
                REQUIRE(named_entry.present);
                // Spec MUST (`membership`): the user's membership in the room.
                REQUIRE(membership_of(unnamed_entry) == "join");
                // Spec MUST (`membership`): the user's membership in the room.
                REQUIRE(membership_of(named_entry) == "join");
                // Spec MUST (`bump_stamp`): an integer for the room's last proper activity.
                auto const* stamp = int_member(unnamed_entry.value, "bump_stamp");
                REQUIRE(stamp != nullptr);
                // Spec MUST (`bump_stamp`): a stream position, so greater than zero once the room has activity.
                REQUIRE(*stamp > 0);
                // Spec MUST (`lists`): the names of the lists the room matched.
                auto const* lists = object_member_as_array(unnamed_entry.value, "lists");
                REQUIRE(lists != nullptr);
                // Spec MUST (`lists`): one entry per list whose range holds the room; the request has one list.
                REQUIRE(lists->size() == 1U);
                // Spec MUST (`lists`): the entry is the list's name.
                REQUIRE(std::get<std::string>(lists->front().storage()) == "all");
            }

            THEN("the unnamed room has bob as its hero and the named room has none")
            {
                // Spec MUST (`heroes`): present when the room has no name.
                auto const* heroes = object_member_as_array(unnamed_entry.value, "heroes");
                REQUIRE(heroes != nullptr);
                // Spec MUST (`heroes`): the users /v3/sync `m.heroes` names: the one other member.
                REQUIRE(heroes->size() == 1U);
                auto const* hero_id = string_member(std::get<json::Object>(heroes->front().storage()), "user_id");
                REQUIRE(hero_id != nullptr);
                // Spec MUST (`heroes`): each hero carries its `user_id`.
                REQUIRE(*hero_id == "@bob:example.org");
                // Spec MUST (`heroes`): "only if the room has no name".
                REQUIRE(object_member(named_entry.value, "heroes") == nullptr);
            }
        }
    }
}

// Spec: MSC4186 — "Room result", `name`: "Can be `null` if the name has been removed."
SCENARIO("MSC4186 a removed room name is sent as null", "[sync][sliding-sync][conformance][msc4186][room-result]")
{
    GIVEN("alice's named room, sent on her connection")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room_id = make_room(rt, alice, R"({"name":"Old name"})");
        auto const pos = pos_of(sliding(rt, alice, list_body));

        WHEN("she removes the name and syncs from the pos")
        {
            expect_ok(rt, alice, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.name/",
                      R"({"name":""})");
            auto const result = sliding(rt, alice, list_body, pos);
            REQUIRE(result.response.status == 200U);
            auto const entry = room_entry(result.response.body, room_id);

            THEN("the room's name is null")
            {
                // Spec MUST: a room whose name changed is sent in the incremental response.
                REQUIRE(entry.present);
                auto const* name = object_member(entry.value, "name");
                // Spec MUST: a removed name is sent, as `null`, not left out.
                REQUIRE(name != nullptr);
                // Spec MUST: a removed name is `null`.
                REQUIRE(std::holds_alternative<std::nullptr_t>(name->storage()));
            }
        }
    }

    GIVEN("alice's named room, sent on a connection that asks for no timeline and no required_state")
    {
        constexpr auto bare_body =
            std::string_view{R"({"lists":{"all":{"ranges":[[0,99]],"required_state":[],"timeline_limit":0}}})"};
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room_id = make_room(rt, alice, R"({"name":"Old name"})");
        auto const pos = pos_of(sliding(rt, alice, bare_body));

        WHEN("she removes the name and syncs from the pos")
        {
            expect_ok(rt, alice, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.name/",
                      R"({"name":""})");
            auto const result = sliding(rt, alice, bare_body, pos);
            REQUIRE(result.response.status == 200U);
            auto const entry = room_entry(result.response.body, room_id);

            THEN("the room is sent, with its name null, though nothing else of it changed")
            {
                // Spec MUST: a room whose name changed is sent in the incremental response.
                REQUIRE(entry.present);
                auto const* name = object_member(entry.value, "name");
                // Spec MUST: a removed name is sent, as `null`, not left out.
                REQUIRE(name != nullptr);
                // Spec MUST: a removed name is `null`; the change is the room's, so the room is sent with it.
                REQUIRE(std::holds_alternative<std::nullptr_t>(name->storage()));
            }

            AND_WHEN("she syncs again from that response's pos")
            {
                auto const again = sliding(rt, alice, bare_body, pos_of(result));
                REQUIRE(again.response.status == 200U);

                THEN("the room is not sent again: its name has not changed since")
                {
                    // Spec MUST: an incremental response carries a room only when something of it changed.
                    REQUIRE_FALSE(room_entry(again.response.body, room_id).present);
                }
            }
        }
    }
}

// Spec: MSC4186 — "Lists": the server list holds rooms the user has "knocked on, left, or been kicked or banned
// from"; "Rooms the user has been banned from, but never joined, should not be part of the list"; a room left of the
// user's own accord only if "previously sent to the client in that connection".
SCENARIO("MSC4186 lists hold kicked, knocked and previously sent left rooms, and not a ban of a room never joined",
         "[sync][sliding-sync][conformance][msc4186][lists]")
{
    GIVEN("alice joined to bob's room, a knock room of bob's, and a room of bob's alice never joined")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const shared = make_room(rt, bob, R"({"preset":"public_chat"})");
        expect_ok(rt, alice, "POST", "/_matrix/client/v3/rooms/" + shared + "/join", "{}");
        auto const knock_room = make_room(
            rt, bob,
            R"({"initial_state":[{"type":"m.room.join_rules","state_key":"","content":{"join_rule":"knock"}}]})");
        auto const never_joined = make_room(rt, bob, R"({"preset":"public_chat"})");
        auto const pos = pos_of(sliding(rt, alice, list_body));

        WHEN("bob kicks alice and then speaks, alice knocks, and bob bans alice from the room she never joined")
        {
            expect_ok(rt, bob, "POST", "/_matrix/client/v3/rooms/" + shared + "/kick",
                      R"({"user_id":"@alice:example.org"})");
            send_text(rt, bob, shared, "after-the-kick");
            expect_ok(rt, alice, "POST", "/_matrix/client/v3/knock/" + knock_room, "{}");
            expect_ok(rt, bob, "POST", "/_matrix/client/v3/rooms/" + never_joined + "/ban",
                      R"({"user_id":"@alice:example.org"})");
            auto const result = sliding(rt, alice, list_body, pos);
            REQUIRE(result.response.status == 200U);
            auto const kicked = room_entry(result.response.body, shared);
            auto const knocked = room_entry(result.response.body, knock_room);

            THEN("the kicked room is listed as left, with her kick and nothing after it")
            {
                // Spec MUST: a room the user was kicked from is in the list.
                REQUIRE(kicked.present);
                // Spec MUST: a room the user was kicked from is in the list, with its membership.
                REQUIRE(membership_of(kicked) == "leave");
                // Spec MUST: a departed room is sent as of the departure: its timeline ends at the kick.
                REQUIRE(timeline_types(kicked) == std::vector<std::string>{"m.room.member"});
                // Spec MUST: nothing after the departure is sent.
                REQUIRE(result.response.body.find("after-the-kick") == std::string::npos);
            }

            THEN("the knocked room is listed with its stripped state")
            {
                // Spec MUST: a room the user has knocked on is in the list.
                REQUIRE(knocked.present);
                // Spec MUST: a knocked room is in the list, with its membership.
                REQUIRE(membership_of(knocked) == "knock");
                // Spec MUST: "Invite/knock/rejections" carry `stripped_state`.
                REQUIRE(object_member_as_array(knocked.value, "stripped_state") != nullptr);
                // Spec MUST: a knocked room is sent its stripped state in place of a timeline.
                REQUIRE(object_member(knocked.value, "timeline") == nullptr);
            }

            THEN("the room she was banned from without joining is not listed")
            {
                // Spec: "Rooms the user has been banned from, but never joined, should not be part of the list".
                REQUIRE_FALSE(room_entry(result.response.body, never_joined).present);
            }
        }
    }

    GIVEN("a room alice left before her connection began, and one she leaves after it was sent")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const left_before = make_room(rt, alice, "{}");
        expect_ok(rt, alice, "POST", "/_matrix/client/v3/rooms/" + left_before + "/leave", "{}");
        auto const left_after = make_room(rt, alice, "{}");
        auto const pos = pos_of(sliding(rt, alice, list_body));

        WHEN("she leaves the second and syncs from the pos")
        {
            expect_ok(rt, alice, "POST", "/_matrix/client/v3/rooms/" + left_after + "/leave", "{}");
            auto const result = sliding(rt, alice, list_body, pos);
            REQUIRE(result.response.status == 200U);

            THEN("only the room the connection was sent is listed, as left")
            {
                auto const entry = room_entry(result.response.body, left_after);
                // Spec MUST: a room left of the user's own accord, previously sent on the connection, is listed.
                REQUIRE(entry.present);
                // Spec MUST: the room carries the user's membership, `leave`.
                REQUIRE(membership_of(entry) == "leave");
                // Spec MUST: a room left of the user's own accord is listed only if previously sent on the connection.
                REQUIRE_FALSE(room_entry(result.response.body, left_before).present);
            }
        }
    }
}

// Spec: MSC4186 — room config `timeline_limit`: "The maximum number of timeline events to return per response"; and
// "Lists": a room the user was banned from after joining is in the list, sent as of the departure. C-S API v1.19,
// "History visibility": an event is visible when the history was `world_readable`, or the user's membership was `join`,
// at the event; so a ban after leaving is visible only in a `world_readable` room.
SCENARIO("MSC4186 a departed room's timeline holds at most timeline_limit events",
         "[sync][sliding-sync][conformance][msc4186][lists]")
{
    GIVEN("alice joined to two of bob's rooms, one world_readable and one shared, both sent on her connection")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const readable =
            make_room(rt, bob,
                      R"({"preset":"public_chat","initial_state":[{"type":"m.room.history_visibility","state_key":"",)"
                      R"("content":{"history_visibility":"world_readable"}}]})");
        auto const shared = make_room(rt, bob, R"({"preset":"public_chat"})");
        for (auto const& room_id : {readable, shared})
        {
            expect_ok(rt, alice, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", "{}");
        }
        auto const pos = pos_of(sliding(rt, alice, list_body));

        WHEN("alice leaves both, bob bans her from both, and she syncs with a timeline_limit of 1")
        {
            for (auto const& room_id : {readable, shared})
            {
                expect_ok(rt, alice, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", "{}");
                expect_ok(rt, bob, "POST", "/_matrix/client/v3/rooms/" + room_id + "/ban",
                          R"({"user_id":"@alice:example.org"})");
            }
            auto const result = sliding(rt, alice, list_body, pos);
            REQUIRE(result.response.status == 200U);

            THEN("the world_readable room is sent as banned with the ban alone, and a prev_batch to reach her leave")
            {
                auto const entry = room_entry(result.response.body, readable);
                // Spec MUST: a room the user was banned from after joining is in the list.
                REQUIRE(entry.present);
                // Spec MUST: a room the user was banned from after joining is in the list, with its membership.
                REQUIRE(membership_of(entry) == "ban");
                // Spec MUST: at most `timeline_limit` events per response, and the newest of them: the ban.
                REQUIRE(timeline_memberships(entry) == std::vector<std::string>{"ban"});
                // Spec MUST: a timeline with older events behind it carries `prev_batch` to paginate to them.
                REQUIRE(string_member(entry.value, "prev_batch") != nullptr);
            }
            THEN("the shared room's timeline is her leave, the newest event she may see, not the ban she may not")
            {
                auto const entry = room_entry(result.response.body, shared);
                // Spec MUST: a room the user was banned from after joining is in the list.
                REQUIRE(entry.present);
                // Spec MUST: a room the user was banned from after joining is in the list, with its membership.
                REQUIRE(membership_of(entry) == "ban");
                // Spec MUST: the ban, sent while she was not joined to a shared room, is not visible to her, and
                // `timeline_limit` counts only the events she may see.
                REQUIRE(timeline_memberships(entry) == std::vector<std::string>{"leave"});
            }
        }
    }
}

// Spec: MSC4186 — "RequiredStateRequest": `include` lists the state to return, an omitted `type` or `state_key`
// matching every value; `exclude` filters state out of what `include` returns; with `lazy_members`, member events are
// those of the timeline's senders. "Combining room configs": a room matched by several configs is sent the union of
// the state each returns, one config's `exclude` never filtering another's `include`.
SCENARIO("MSC4186 required_state objects return what include names, less what exclude names",
         "[sync][sliding-sync][conformance][msc4186][room-result]")
{
    GIVEN("bob's named room with a topic, which alice has joined, and bob's message last in it")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const room_id = make_room(rt, bob, R"({"preset":"public_chat","name":"Named","topic":"A topic"})");
        expect_ok(rt, alice, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", "{}");
        send_text(rt, bob, room_id, "last");
        auto const list = [](std::string const& required_state) {
            return R"({"lists":{"all":{"ranges":[[0,99]],"required_state":)" + required_state +
                   R"(,"timeline_limit":1}})";
        };

        WHEN("a list includes every state event but the topic")
        {
            auto const result =
                sliding(rt, alice, list(R"({"include":[{}],"exclude":[{"type":"m.room.topic"}]})") + "}");
            REQUIRE(result.response.status == 200U);
            auto const keys = required_state_keys(room_entry(result.response.body, room_id));

            THEN("the room's state is sent without its topic")
            {
                // Spec MUST: an element with no `type` and no `state_key` matches every state event.
                REQUIRE(holds_type(keys, "m.room.create"));
                REQUIRE(holds_type(keys, "m.room.name"));
                // Spec MUST: state an `exclude` element matches is not returned.
                REQUIRE_FALSE(holds_type(keys, "m.room.topic"));
            }
        }

        WHEN("a list includes only events of one state key, with the type omitted")
        {
            auto const result = sliding(rt, alice, list(R"({"include":[{"state_key":"@alice:example.org"}]})") + "}");
            REQUIRE(result.response.status == 200U);
            auto const keys = required_state_keys(room_entry(result.response.body, room_id));

            THEN("only alice's member event is sent")
            {
                // Spec MUST: an omitted `type` matches every type, and the `state_key` only that key.
                REQUIRE(keys == std::vector<std::pair<std::string, std::string>>{
                                    {"m.room.member", "@alice:example.org"}
                });
            }
        }

        WHEN("a list includes everything with lazy_members")
        {
            auto const result = sliding(rt, alice, list(R"({"include":[{}],"lazy_members":true})") + "}");
            REQUIRE(result.response.status == 200U);
            auto const keys = required_state_keys(room_entry(result.response.body, room_id));

            THEN("the non-member state is sent, and the member events are those of the timeline's sender")
            {
                // Spec MUST: `lazy_members` returns the members of the timeline's senders, not every member.
                // Spec MUST: `lazy_members` does not hold back the non-member state `include` names.
                REQUIRE(holds_type(keys, "m.room.name"));
                auto const members = std::ranges::count_if(keys, [](auto const& key) {
                    return key.first == "m.room.member";
                });
                REQUIRE(members == 1);
                // Spec MUST: the member sent is the timeline's sender's.
                REQUIRE(std::ranges::find(keys, std::pair<std::string, std::string>{"m.room.member",
                                                                                    "@bob:example.org"}) != keys.end());
            }
        }

        WHEN("a list excludes the topic and a subscription to the room includes it")
        {
            auto const result = sliding(
                rt, alice,
                list(R"({"include":[{}],"exclude":[{"type":"m.room.topic"}]})") + R"(,"room_subscriptions":{")" +
                    room_id +
                    R"(":{"required_state":{"include":[{"type":"m.room.topic","state_key":""}]},"timeline_limit":1}}})");
            REQUIRE(result.response.status == 200U);
            auto const keys = required_state_keys(room_entry(result.response.body, room_id));

            THEN("the room is sent the union: its topic too")
            {
                // Spec MUST: combined configs return the union; one config's `exclude` does not filter another's.
                REQUIRE(holds_type(keys, "m.room.topic"));
                // Spec MUST: and what the list's config returns.
                REQUIRE(holds_type(keys, "m.room.name"));
            }
        }
    }
}

// Spec: MSC4186 — "Room result", `is_dm`: "Must be included in an incremental sync if the DM state changes."
SCENARIO("MSC4186 a room whose DM status changes is sent again", "[sync][sliding-sync][conformance][msc4186][is-dm]")
{
    GIVEN("alice's room, sent on her connection as not a DM")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room_id = make_room(rt, alice, "{}");
        auto const pos = pos_of(sliding(rt, alice, list_body));

        WHEN("she marks it a DM in m.direct, and nothing else happens in it")
        {
            expect_ok(rt, alice, "PUT", "/_matrix/client/v3/user/%40alice%3Aexample.org/account_data/m.direct",
                      R"({"@bob:example.org":[")" + room_id + R"("]})");
            auto const result = sliding(rt, alice, list_body, pos);
            REQUIRE(result.response.status == 200U);
            auto const entry = room_entry(result.response.body, room_id);

            THEN("the room is sent with is_dm true")
            {
                // Spec MUST: `is_dm` is included in an incremental sync when the DM state changes.
                REQUIRE(entry.present);
                auto const* is_dm = merovingian::tests::bool_member(entry.value, "is_dm");
                REQUIRE(is_dm != nullptr);
                // Spec MUST: `is_dm` is true once the room is a DM.
                REQUIRE(*is_dm);
            }
        }
    }
}

// Spec: MSC4538, MSC4543, MSC4548, MSC4551, MSC4508 — each extension's request and response key is its prefixed name
// (`org.matrix.msc4538.to_device`, ...). This server also keeps the bare names (ADR-0865): it answers each key the
// request used.
SCENARIO("MSC4186 extensions are answered under the names the request used",
         "[sync][sliding-sync][conformance][msc4186][extensions]")
{
    GIVEN("a user")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");

        WHEN("she enables to_device and e2ee by their prefixed names only, and account_data by both names")
        {
            auto const result = sliding(
                rt, alice,
                R"({"extensions":{"org.matrix.msc4538.to_device":{"enabled":true},"org.matrix.msc4543.e2ee":{"enabled":true},)"
                R"("org.matrix.msc4548.account_data":{"enabled":true},"account_data":{"enabled":true}}})");
            REQUIRE(result.response.status == 200U);
            auto const body = parse_object(result.response.body);
            auto const* extensions = object_member_as_object(body, "extensions");
            REQUIRE(extensions != nullptr);

            THEN("each is answered under each name it was asked by, and no other")
            {
                // Spec MUST: an extension asked for by its MSC-prefixed name is answered under that name.
                REQUIRE(object_member(*extensions, "org.matrix.msc4538.to_device") != nullptr);
                // Spec MUST: and not under a name the request did not use.
                REQUIRE(object_member(*extensions, "to_device") == nullptr);
                // Spec MUST: an extension asked for by its MSC-prefixed name is answered under that name.
                REQUIRE(object_member(*extensions, "org.matrix.msc4543.e2ee") != nullptr);
                // Spec MUST: and not under a name the request did not use.
                REQUIRE(object_member(*extensions, "e2ee") == nullptr);
                // Spec MUST: an extension asked for under both names is answered under each.
                REQUIRE(object_member(*extensions, "org.matrix.msc4548.account_data") != nullptr);
                // Spec MUST: an extension asked for under both names is answered under each.
                REQUIRE(object_member(*extensions, "account_data") != nullptr);
            }
        }

        WHEN("the client reads /versions")
        {
            auto const versions = call(rt, {}, "GET", "/_matrix/client/versions", {});
            REQUIRE(versions.response.status == 200U);
            auto const body = parse_object(versions.response.body);
            auto const* unstable = object_member_as_object(body, "unstable_features");
            REQUIRE(unstable != nullptr);

            THEN("each extension MSC is advertised")
            {
                for (auto const* flag : {"org.matrix.msc4508", "org.matrix.msc4538", "org.matrix.msc4543",
                                         "org.matrix.msc4548", "org.matrix.msc4551"})
                {
                    auto const* advertised = merovingian::tests::bool_member(*unstable, flag);
                    // Spec SHOULD: a server supporting an unstable MSC advertises it in `unstable_features`.
                    REQUIRE(advertised != nullptr);
                    // Spec SHOULD: the flag is true while the MSC is supported.
                    REQUIRE(*advertised);
                }
            }
        }
    }
}

// Spec: MSC4543 — "Device lists": "The response to a request without `pos` carries no `device_lists`."
SCENARIO("MSC4543 the e2ee extension sends no device lists without a pos",
         "[sync][sliding-sync][conformance][msc4543][e2ee]")
{
    GIVEN("a user enabling the e2ee extension")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        constexpr auto body = std::string_view{R"({"extensions":{"e2ee":{"enabled":true}}})"};

        WHEN("she syncs without a pos and then with the pos she was given")
        {
            auto const first = sliding(rt, alice, body);
            auto const second = sliding(rt, alice, body, pos_of(first));
            auto const e2ee_of = [](hs::DispatchResult const& result) {
                auto const parsed = parse_object(result.response.body);
                auto const* extensions = object_member_as_object(parsed, "extensions");
                auto const* e2ee = extensions == nullptr ? nullptr : object_member_as_object(*extensions, "e2ee");
                REQUIRE(e2ee != nullptr);
                return e2ee == nullptr ? json::Object{} : *e2ee;
            };

            THEN("the first carries no device_lists and both carry the key counts")
            {
                // Spec MUST: no `device_lists` in the response to a request without `pos`.
                REQUIRE(object_member(e2ee_of(first), "device_lists") == nullptr);
                // Spec MUST: the section is included in the response to a request without `pos`.
                REQUIRE(object_member(e2ee_of(first), "device_one_time_keys_count") != nullptr);
                // Spec MUST: a request with a pos is answered as usual.
                REQUIRE(second.response.status == 200U);
            }
        }
    }
}

// Spec: MSC4548 — "Room account data": "Room account data MUST be returned for an in-scope room regardless of the
// user's membership in it", and only for in-scope rooms.
SCENARIO("MSC4548 room account data follows the extension's scope, whatever the membership",
         "[sync][sliding-sync][conformance][msc4548][account-data]")
{
    GIVEN("alice invited to bob's room, with room account data on it, and room account data on a room of her own")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const invited = make_room(rt, bob, R"({"invite":["@alice:example.org"]})");
        auto const own = make_room(rt, alice, "{}");
        // The room account data API takes any membership row (ADR-0197); the tags API needs a join.
        for (auto const& room_id : {invited, own})
        {
            expect_ok(rt, alice, "PUT",
                      "/_matrix/client/v3/user/%40alice%3Aexample.org/rooms/" + room_id +
                          "/account_data/org.example.note",
                      R"({"note":"kept"})");
        }

        WHEN("the extension's scope is a subscription to the invited room only")
        {
            auto const result =
                sliding(rt, alice,
                        R"({"lists":{"all":{"ranges":[[0,99]],"required_state":[],"timeline_limit":0}},)"
                        R"("room_subscriptions":{")" +
                            invited +
                            R"(":{"required_state":[],"timeline_limit":0}},)"
                            R"("extensions":{"account_data":{"enabled":true,"lists":[],"rooms":[")" +
                            invited + R"("]}}})");
            REQUIRE(result.response.status == 200U);
            auto const body = parse_object(result.response.body);
            auto const* extensions = object_member_as_object(body, "extensions");
            REQUIRE(extensions != nullptr);
            auto const* account_data = object_member_as_object(*extensions, "account_data");
            REQUIRE(account_data != nullptr);
            auto const* rooms = object_member_as_object(*account_data, "rooms");
            REQUIRE(rooms != nullptr);

            THEN("the invited room's account data is sent, and the out-of-scope room's is not")
            {
                // Spec MUST: account data for an in-scope room regardless of membership.
                REQUIRE(object_member(*rooms, invited) != nullptr);
                // Spec MUST: `rooms` covers in-scope rooms only.
                REQUIRE(object_member(*rooms, own) == nullptr);
            }
        }
    }
}
