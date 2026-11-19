// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Invited rooms in MSC4186 simplified sliding sync lists, and the long-poll a new invite ends (ADR-0864).
//
// Spec: MSC4186 "Lists" (`filters.is_invite`; an unfiltered list holds the rooms the user is invited to) and the room
// response's `invite_state` (stripped state only: no `timeline`, no `required_state`); C-S API v1.19, "Room history
// visibility": a user who has not joined a room may not view its events. The invites are made by /createRoom's
// `invite` and by POST /invite, the two paths a local invite takes.

#include "../support/E2eeCapsSupport.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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
using merovingian::tests::object_member;
using merovingian::tests::object_member_as_array;
using merovingian::tests::object_member_as_object;
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

constexpr auto simplified_path = std::string_view{"/_matrix/client/unstable/org.matrix.simplified_msc3575/sync"};
constexpr auto benandez = std::string_view{"@benandez:example.org"};

// The body the Persephone client sends: one unfiltered growing list, its own membership in required_state, and the
// five extensions, with no room subscriptions.
constexpr auto persephone_body = std::string_view{
    R"({"lists":{"rooms":{"ranges":[[0,99]],"required_state":[["m.room.member","$ME"]],"timeline_limit":20}},)"
    R"("extensions":{"to_device":{"enabled":true},"e2ee":{"enabled":true},"account_data":{"enabled":true},)"
    R"("receipts":{"enabled":true},"typing":{"enabled":true}}})"};

[[nodiscard]] auto call(hs::ClientServerRuntime& rt, std::string const& token, std::string const& method,
                        std::string const& target, std::string const& body) -> hs::DispatchResult
{
    return hs::handle_client_server_request(rt, {method, target, token, body}, /*can_wait=*/false);
}

[[nodiscard]] auto register_user(hs::ClientServerRuntime& rt, std::string_view localpart) -> std::string
{
    auto const registered = call(rt, {}, "POST", "/_matrix/client/v3/register",
                                 merovingian::tests::registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.response.status == 200U);
    return merovingian::tests::access_token_from(registered.response.body);
}

[[nodiscard]] auto make_room(hs::ClientServerRuntime& rt, std::string const& token, std::string const& body)
    -> std::string
{
    auto const created = call(rt, token, "POST", "/_matrix/client/v3/createRoom", body);
    REQUIRE(created.response.status == 200U);
    return merovingian::tests::string_field(created.response.body, "room_id");
}

auto expect_ok(hs::ClientServerRuntime& rt, std::string const& token, std::string const& method,
               std::string const& target, std::string const& body) -> void
{
    REQUIRE(call(rt, token, method, target, body).response.status == 200U);
}

auto invite(hs::ClientServerRuntime& rt, std::string const& token, std::string const& room_id, std::string_view user_id)
    -> void
{
    expect_ok(rt, token, "POST", "/_matrix/client/v3/rooms/" + room_id + "/invite",
              R"({"user_id":")" + std::string{user_id} + R"("})");
}

auto send_text(hs::ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
               std::string const& txn, std::string const& text) -> void
{
    expect_ok(rt, token, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/" + txn,
              R"({"msgtype":"m.text","body":")" + text + R"("})");
}

// One sliding sync request on the simplified path. With a timeout and `can_wait` it may park (needs_wait), as the
// long-poll of a waiting client does; the notifier reruns the same request when it is woken.
[[nodiscard]] auto poll(hs::ClientServerRuntime& rt, std::string const& token, std::string_view body,
                        std::string const& pos, std::uint64_t timeout_ms) -> hs::DispatchResult
{
    auto target = std::string{simplified_path};
    auto separator = '?';
    if (!pos.empty())
    {
        target += "?pos=" + pos;
        separator = '&';
    }
    if (timeout_ms > 0U)
    {
        target += separator;
        target += "timeout=" + std::to_string(timeout_ms);
    }
    return hs::handle_client_server_request(rt, {"POST", target, token, std::string{body}},
                                            /*can_wait=*/timeout_ms > 0U);
}

[[nodiscard]] auto pos_of(hs::DispatchResult const& result) -> std::string
{
    REQUIRE(result.status == hs::DispatchResult::Status::complete);
    REQUIRE(result.response.status == 200U);
    auto const body = parse_object(result.response.body);
    auto const* pos = string_member(body, "pos");
    REQUIRE(pos != nullptr);
    return *pos;
}

// The room IDs of one list's SYNC ops, in op order.
[[nodiscard]] auto list_rooms(std::string const& response_body, std::string_view list) -> std::vector<std::string>
{
    auto rooms = std::vector<std::string>{};
    auto const body = parse_object(response_body);
    auto const* lists = object_member_as_object(body, "lists");
    REQUIRE(lists != nullptr);
    auto const* named = object_member_as_object(*lists, list);
    REQUIRE(named != nullptr);
    auto const* ops = object_member_as_array(*named, "ops");
    REQUIRE(ops != nullptr);
    for (auto const& op : *ops)
    {
        auto const* ids = object_member(std::get<json::Object>(op.storage()), "room_ids");
        if (ids == nullptr)
        {
            continue;
        }
        for (auto const& id : std::get<json::Array>(ids->storage()))
        {
            rooms.push_back(std::get<std::string>(id.storage()));
        }
    }
    return rooms;
}

[[nodiscard]] auto list_count(std::string const& response_body, std::string_view list) -> std::int64_t
{
    auto const body = parse_object(response_body);
    auto const* lists = object_member_as_object(body, "lists");
    REQUIRE(lists != nullptr);
    auto const* named = object_member_as_object(*lists, list);
    REQUIRE(named != nullptr);
    auto const* count = object_member(*named, "count");
    REQUIRE(count != nullptr);
    return std::get<std::int64_t>(count->storage());
}

[[nodiscard]] auto contains(std::vector<std::string> const& rooms, std::string const& room_id) -> bool
{
    return std::ranges::find(rooms, room_id) != rooms.end();
}

// The response's entry for `room_id`, copied; nullopt-like empty object with `present` false when absent.
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

// The (type, state_key) pairs of an invite_state array.
[[nodiscard]] auto invite_state_keys(json::Object const& room) -> std::vector<std::pair<std::string, std::string>>
{
    auto keys = std::vector<std::pair<std::string, std::string>>{};
    auto const* invite_state = object_member_as_array(room, "invite_state");
    REQUIRE(invite_state != nullptr);
    for (auto const& event : *invite_state)
    {
        auto const& object = std::get<json::Object>(event.storage());
        auto const* type = string_member(object, "type");
        auto const* state_key = string_member(object, "state_key");
        REQUIRE(type != nullptr);
        REQUIRE(state_key != nullptr);
        keys.emplace_back(*type, *state_key);
    }
    return keys;
}

[[nodiscard]] auto has_key(std::vector<std::pair<std::string, std::string>> const& keys, std::string_view type,
                           std::string_view state_key) -> bool
{
    return std::ranges::any_of(keys, [&](auto const& key) {
        return key.first == type && key.second == state_key;
    });
}

// Neither a timeline nor required_state: what a user only invited to a room may be sent.
[[nodiscard]] auto carries_no_room_content(json::Object const& room) -> bool
{
    auto const* timeline = object_member_as_array(room, "timeline");
    auto const* required_state = object_member_as_array(room, "required_state");
    return (timeline == nullptr || timeline->empty()) && (required_state == nullptr || required_state->empty()) &&
           object_member(room, "prev_batch") == nullptr;
}

[[nodiscard]] auto start_server() -> hs::ClientServerStartResult
{
    return hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
}

// @james and @benandez, benandez joined to one room of james's and caught up by an initial sliding sync: the state of
// the production report (rooms_seen=1).
struct InviteFixture final
{
    std::string james{};
    std::string benandez_token{};
    std::string shared_room{};
    std::string pos{};
};

[[nodiscard]] auto caught_up_invitee(hs::ClientServerRuntime& rt) -> InviteFixture
{
    auto fixture = InviteFixture{};
    fixture.james = register_user(rt, "james");
    fixture.benandez_token = register_user(rt, "benandez");
    fixture.shared_room = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
    invite(rt, fixture.james, fixture.shared_room, benandez);
    expect_ok(rt, fixture.benandez_token, "POST", "/_matrix/client/v3/rooms/" + fixture.shared_room + "/join", "{}");
    fixture.pos = pos_of(poll(rt, fixture.benandez_token, persephone_body, {}, 0U));
    return fixture;
}

} // namespace

SCENARIO("A waiting sliding sync long-poll returns at once when /createRoom invites the user",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("benandez caught up, and a long-poll from his pos parked because nothing has changed")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        REQUIRE(poll(rt, fixture.benandez_token, persephone_body, fixture.pos, 5000U).status ==
                hs::DispatchResult::Status::needs_wait);

        WHEN("james creates a room inviting benandez, and the woken long-poll runs again")
        {
            auto const room_id = make_room(
                rt, fixture.james, R"({"preset":"private_chat","name":"Plans","invite":["@benandez:example.org"]})");
            auto const woken = poll(rt, fixture.benandez_token, persephone_body, fixture.pos, 5000U);

            THEN("it answers with a new pos, the room in the list and in rooms with its stripped invite state only")
            {
                REQUIRE(woken.status == hs::DispatchResult::Status::complete);
                REQUIRE(pos_of(woken) != fixture.pos);
                REQUIRE(contains(list_rooms(woken.response.body, "rooms"), room_id));
                REQUIRE(list_count(woken.response.body, "rooms") == 2);

                auto const entry = room_entry(woken.response.body, room_id);
                REQUIRE(entry.present);
                REQUIRE(carries_no_room_content(entry.value));
                auto const keys = invite_state_keys(entry.value);
                REQUIRE(has_key(keys, "m.room.member", benandez));
                REQUIRE(has_key(keys, "m.room.create", ""));
                REQUIRE(has_key(keys, "m.room.join_rules", ""));
                REQUIRE(has_key(keys, "m.room.name", ""));
            }
        }
    }
}

SCENARIO("A waiting sliding sync long-poll returns at once when POST /invite invites the user",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("a room of james's benandez is not in, and benandez's long-poll parked at his pos")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        auto const room_id = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
        auto const parked_pos = pos_of(poll(rt, fixture.benandez_token, persephone_body, fixture.pos, 0U));
        REQUIRE(poll(rt, fixture.benandez_token, persephone_body, parked_pos, 5000U).status ==
                hs::DispatchResult::Status::needs_wait);

        WHEN("james invites benandez, and the woken long-poll runs again")
        {
            invite(rt, fixture.james, room_id, benandez);
            auto const woken = poll(rt, fixture.benandez_token, persephone_body, parked_pos, 5000U);

            THEN("it answers with the room and its invite_state, and no timeline or required_state")
            {
                REQUIRE(woken.status == hs::DispatchResult::Status::complete);
                REQUIRE(contains(list_rooms(woken.response.body, "rooms"), room_id));
                auto const entry = room_entry(woken.response.body, room_id);
                REQUIRE(entry.present);
                REQUIRE(carries_no_room_content(entry.value));
                REQUIRE(has_key(invite_state_keys(entry.value), "m.room.member", benandez));
            }
        }
    }
}

SCENARIO("Sliding sync lists hold invited rooms unless is_invite excludes them, ordered by the invite's position",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("benandez joined to an old room, then invited to a room, then a message in a second joined room")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        auto const invited = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
        invite(rt, fixture.james, invited, benandez);
        auto const busy = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
        invite(rt, fixture.james, busy, benandez);
        expect_ok(rt, fixture.benandez_token, "POST", "/_matrix/client/v3/rooms/" + busy + "/join", "{}");
        send_text(rt, fixture.james, busy, "t1", "latest");

        WHEN("a fresh connection asks for an unfiltered list, an is_invite:true list and an is_invite:false list")
        {
            auto const answered =
                poll(rt, fixture.benandez_token,
                     R"({"conn_id":"lists","lists":{)"
                     R"("all":{"ranges":[[0,9]],"sort":["by_recency"]},)"
                     R"("invites":{"ranges":[[0,9]],"filters":{"is_invite":true}},)"
                     R"("joined":{"ranges":[[0,9]],"filters":{"is_invite":false},"sort":["by_recency"]}}})",
                     {}, 0U);
            REQUIRE(answered.response.status == 200U);

            THEN("the unfiltered list holds all three, the invite ranked by its position between the joined rooms")
            {
                REQUIRE(list_rooms(answered.response.body, "all") ==
                        std::vector<std::string>{busy, invited, fixture.shared_room});
            }

            THEN("is_invite:true holds only the invited room and is_invite:false only the joined ones")
            {
                REQUIRE(list_rooms(answered.response.body, "invites") == std::vector<std::string>{invited});
                REQUIRE(list_rooms(answered.response.body, "joined") ==
                        std::vector<std::string>{busy, fixture.shared_room});
            }

            THEN("the invited room carries invite_state and the joined rooms do not")
            {
                auto const invited_entry = room_entry(answered.response.body, invited);
                REQUIRE(invited_entry.present);
                REQUIRE(object_member(invited_entry.value, "invite_state") != nullptr);
                REQUIRE(carries_no_room_content(invited_entry.value));
                auto const joined_entry = room_entry(answered.response.body, busy);
                REQUIRE(joined_entry.present);
                REQUIRE(object_member(joined_entry.value, "invite_state") == nullptr);
            }
        }
    }
}

SCENARIO("An invited room reported once is not sent again by the next poll",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("benandez's connection that has been sent james's invite")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        auto const room_id = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
        invite(rt, fixture.james, room_id, benandez);
        auto const reported = poll(rt, fixture.benandez_token, persephone_body, fixture.pos, 0U);
        REQUIRE(room_entry(reported.response.body, room_id).present);
        auto const next_pos = pos_of(reported);

        WHEN("he polls again from the new pos with nothing changed")
        {
            auto const immediate = poll(rt, fixture.benandez_token, persephone_body, next_pos, 0U);
            auto const waiting = poll(rt, fixture.benandez_token, persephone_body, next_pos, 5000U);

            THEN("the room is not in rooms, and a long-poll parks")
            {
                REQUIRE_FALSE(room_entry(immediate.response.body, room_id).present);
                REQUIRE(waiting.status == hs::DispatchResult::Status::needs_wait);
            }
        }

        WHEN("james invites him again after he rejects, so the invite is a new one")
        {
            expect_ok(rt, fixture.benandez_token, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", "{}");
            auto const after_leave = pos_of(poll(rt, fixture.benandez_token, persephone_body, next_pos, 0U));
            invite(rt, fixture.james, room_id, benandez);
            auto const again = poll(rt, fixture.benandez_token, persephone_body, after_leave, 5000U);

            THEN("the long-poll returns and the room is sent again with its invite_state")
            {
                REQUIRE(again.status == hs::DispatchResult::Status::complete);
                auto const entry = room_entry(again.response.body, room_id);
                REQUIRE(entry.present);
                REQUIRE(object_member(entry.value, "invite_state") != nullptr);
            }
        }
    }
}

SCENARIO("A rejected, withdrawn or accepted invite changes the invitee's sliding sync list",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("benandez's connection that has been sent james's invite, and the pos of that response")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        auto const room_id = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
        send_text(rt, fixture.james, room_id, "t1", "before the invite");
        invite(rt, fixture.james, room_id, benandez);
        auto const reported = poll(rt, fixture.benandez_token, persephone_body, fixture.pos, 0U);
        REQUIRE(contains(list_rooms(reported.response.body, "rooms"), room_id));
        auto const pos = pos_of(reported);

        WHEN("benandez rejects the invite")
        {
            expect_ok(rt, fixture.benandez_token, "POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", "{}");
            auto const next = poll(rt, fixture.benandez_token, persephone_body, pos, 5000U);

            THEN("his long-poll returns and the room has left the list")
            {
                REQUIRE(next.status == hs::DispatchResult::Status::complete);
                REQUIRE(list_count(next.response.body, "rooms") == 1);
                REQUIRE(list_rooms(next.response.body, "rooms") == std::vector<std::string>{fixture.shared_room});
                REQUIRE_FALSE(room_entry(next.response.body, room_id).present);
            }
        }

        WHEN("james withdraws the invite by kicking him")
        {
            expect_ok(rt, fixture.james, "POST", "/_matrix/client/v3/rooms/" + room_id + "/kick",
                      R"({"user_id":"@benandez:example.org"})");
            auto const next = poll(rt, fixture.benandez_token, persephone_body, pos, 5000U);

            THEN("his long-poll returns and the room has left the list")
            {
                REQUIRE(next.status == hs::DispatchResult::Status::complete);
                REQUIRE(list_count(next.response.body, "rooms") == 1);
                REQUIRE_FALSE(contains(list_rooms(next.response.body, "rooms"), room_id));
                REQUIRE_FALSE(room_entry(next.response.body, room_id).present);
            }
        }

        WHEN("benandez accepts the invite")
        {
            expect_ok(rt, fixture.benandez_token, "POST", "/_matrix/client/v3/rooms/" + room_id + "/join", "{}");
            auto const next = poll(rt, fixture.benandez_token, persephone_body, pos, 5000U);

            THEN("the room is sent as a joined room: initial, with a timeline and his member event, no invite_state")
            {
                REQUIRE(next.status == hs::DispatchResult::Status::complete);
                // The room keeps its place in the window (the join is newer than the invite, both newest), so no
                // SYNC op is due; the list still counts it and the room is sent.
                REQUIRE(list_count(next.response.body, "rooms") == 2);
                auto const entry = room_entry(next.response.body, room_id);
                REQUIRE(entry.present);
                REQUIRE(object_member(entry.value, "invite_state") == nullptr);
                auto const* initial = object_member(entry.value, "initial");
                REQUIRE(initial != nullptr);
                REQUIRE(std::get<bool>(initial->storage()));
                auto const* timeline = object_member_as_array(entry.value, "timeline");
                REQUIRE(timeline != nullptr);
                REQUIRE_FALSE(timeline->empty());
                auto const* required_state = object_member_as_array(entry.value, "required_state");
                REQUIRE(required_state != nullptr);
                REQUIRE_FALSE(required_state->empty());
            }
        }
    }
}

SCENARIO("A user only invited to a room is sent none of its timeline or state through a list",
         "[homeserver][sliding-sync][invites][integration][security][csaz-1]")
{
    GIVEN("a room with a message and a topic, to which benandez is invited and has not joined")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        auto const room_id = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
        send_text(rt, fixture.james, room_id, "t1", "secret-message-text");
        invite(rt, fixture.james, room_id, benandez);

        WHEN("he asks for every state event and a long timeline of every listed room")
        {
            auto const answered =
                poll(rt, fixture.benandez_token,
                     R"({"conn_id":"greedy","lists":{"all":{"ranges":[[0,9]],"required_state":[["*","*"]],)"
                     R"("timeline_limit":50,"filters":{"is_invite":true}}}})",
                     {}, 0U);
            REQUIRE(answered.response.status == 200U);

            THEN("the room is listed with stripped state only, and the message is nowhere in the response")
            {
                REQUIRE(list_rooms(answered.response.body, "all") == std::vector<std::string>{room_id});
                auto const entry = room_entry(answered.response.body, room_id);
                REQUIRE(entry.present);
                REQUIRE(carries_no_room_content(entry.value));
                REQUIRE(answered.response.body.find("secret-message-text") == std::string::npos);
                REQUIRE_FALSE(has_key(invite_state_keys(entry.value), "m.room.power_levels", ""));
            }
        }
    }
}

SCENARIO("An invite from an ignored user neither wakes a sliding sync long-poll nor joins a list",
         "[homeserver][sliding-sync][invites][integration][ignoring-users]")
{
    GIVEN("benandez ignores carol, and his long-poll parked at his pos")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        auto const carol = register_user(rt, "carol");
        expect_ok(rt, fixture.benandez_token, "PUT",
                  "/_matrix/client/v3/user/%40benandez%3Aexample.org/account_data/m.ignored_user_list",
                  R"({"ignored_users":{"@carol:example.org":{}}})");
        auto const ignore_pos = pos_of(poll(rt, fixture.benandez_token, persephone_body, fixture.pos, 0U));
        auto const room_id = make_room(rt, carol, R"({"preset":"private_chat"})");
        REQUIRE(poll(rt, fixture.benandez_token, persephone_body, ignore_pos, 5000U).status ==
                hs::DispatchResult::Status::needs_wait);

        WHEN("carol invites him")
        {
            invite(rt, carol, room_id, benandez);
            auto const waiting = poll(rt, fixture.benandez_token, persephone_body, ignore_pos, 5000U);
            auto const immediate = poll(rt, fixture.benandez_token, persephone_body, ignore_pos, 0U);

            THEN("the long-poll stays parked, and an immediate answer lists and sends nothing of the room")
            {
                REQUIRE(waiting.status == hs::DispatchResult::Status::needs_wait);
                REQUIRE(list_count(immediate.response.body, "rooms") == 1);
                REQUIRE_FALSE(room_entry(immediate.response.body, room_id).present);
            }
        }
    }
}

SCENARIO("A response that reports an invite at an unchanged position gets a new page, so it is acknowledged",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("benandez invited by james, and a connection whose one list leaves invites out")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const james = register_user(rt, "james");
        auto const benandez_token = register_user(rt, "benandez");
        auto const room_id = make_room(rt, james, R"({"preset":"private_chat"})");
        invite(rt, james, room_id, benandez);
        constexpr auto joined_only =
            std::string_view{R"({"lists":{"joined":{"ranges":[[0,99]],"required_state":[],"timeline_limit":1,)"
                             R"("filters":{"is_invite":false}}}})"};
        constexpr auto with_invites = std::string_view{
            R"({"lists":{"joined":{"ranges":[[0,99]],"required_state":[],"timeline_limit":1,)"
            R"("filters":{"is_invite":false}},"all":{"ranges":[[0,99]],"required_state":[],"timeline_limit":1}}})"};
        auto const first = poll(rt, benandez_token, joined_only, {}, 0U);
        REQUIRE_FALSE(room_entry(first.response.body, room_id).present);
        auto const pos = pos_of(first);

        WHEN("he adds an unfiltered list with nothing new on the server, then polls from the pos it returned")
        {
            auto const reported = poll(rt, benandez_token, with_invites, pos, 0U);
            auto const reported_pos = pos_of(reported);
            auto const next = poll(rt, benandez_token, with_invites, reported_pos, 0U);

            THEN("the invite is sent once, under a pos of its own, and the next poll does not replay it")
            {
                REQUIRE(room_entry(reported.response.body, room_id).present);
                REQUIRE(reported_pos != pos);
                REQUIRE_FALSE(room_entry(next.response.body, room_id).present);
            }
        }
    }
}

SCENARIO("A new invite no list's filters would hold leaves a sliding sync long-poll parked",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("benandez's connection whose one list holds only encrypted rooms")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const james = register_user(rt, "james");
        auto const benandez_token = register_user(rt, "benandez");
        constexpr auto encrypted_only =
            std::string_view{R"({"lists":{"encrypted":{"ranges":[[0,99]],"required_state":[],"timeline_limit":1,)"
                             R"("filters":{"is_encrypted":true}}}})"};
        auto const pos = pos_of(poll(rt, benandez_token, encrypted_only, {}, 0U));

        WHEN("james invites him to an unencrypted room, and then to an encrypted one")
        {
            // A private_chat room is encrypted by default (rooms::EncryptionPolicy); a public_chat room is not.
            static_cast<void>(make_room(rt, james, R"({"preset":"public_chat","invite":["@benandez:example.org"]})"));
            auto const unencrypted_wait = poll(rt, benandez_token, encrypted_only, pos, 5000U);
            auto const encrypted_room =
                make_room(rt, james, R"({"preset":"private_chat","invite":["@benandez:example.org"]})");
            auto const encrypted_wait = poll(rt, benandez_token, encrypted_only, pos, 5000U);

            THEN("the unencrypted invite leaves the poll parked, and the encrypted one answers it")
            {
                REQUIRE(unencrypted_wait.status == hs::DispatchResult::Status::needs_wait);
                REQUIRE(encrypted_wait.status == hs::DispatchResult::Status::complete);
                REQUIRE(contains(list_rooms(encrypted_wait.response.body, "encrypted"), encrypted_room));
            }
        }
    }
}

SCENARIO("A withdrawn invite outside every window answers a sliding sync long-poll",
         "[homeserver][sliding-sync][invites][integration]")
{
    GIVEN("benandez joined to one room and invited to another, with a window of one room that holds the joined one")
    {
        auto started = start_server();
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const fixture = caught_up_invitee(rt);
        auto const invited_room = make_room(rt, fixture.james, R"({"preset":"private_chat"})");
        invite(rt, fixture.james, invited_room, benandez);
        send_text(rt, fixture.james, fixture.shared_room, "t1", "newer than the invite");
        constexpr auto top_only = std::string_view{
            R"({"lists":{"top":{"ranges":[[0,0]],"sort":["by_recency"],"required_state":[],"timeline_limit":1}}})"};
        auto const first = poll(rt, fixture.benandez_token, top_only, {}, 0U);
        REQUIRE(list_count(first.response.body, "top") == 2);
        REQUIRE(list_rooms(first.response.body, "top") == std::vector<std::string>{fixture.shared_room});
        REQUIRE_FALSE(room_entry(first.response.body, invited_room).present);
        auto const pos = pos_of(first);

        WHEN("james withdraws the invite he was never sent, and benandez's long-poll runs")
        {
            expect_ok(rt, fixture.james, "POST", "/_matrix/client/v3/rooms/" + invited_room + "/kick",
                      R"({"user_id":"@benandez:example.org"})");
            auto const next = poll(rt, fixture.benandez_token, top_only, pos, 5000U);

            THEN("the poll is answered with the list's new count")
            {
                REQUIRE(next.status == hs::DispatchResult::Status::complete);
                REQUIRE(list_count(next.response.body, "top") == 1);
            }
        }
    }
}
