// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Spec: Matrix Server-Server API v1.19, "Checks performed on receipt of a PDU"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
//
// "Whenever a server receives an event from a remote server, the receiving server must ensure that the event: ...
// 4. Passes authorisation rules based on the event's auth events, otherwise it is rejected."
//
// A resident's send_join answer is such a receipt (F-45, ADR-0369): nothing in it is taken on the resident's word.

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/homeserver/AuthorizedSendJoinAnswer.hpp"
#include "merovingian/homeserver/SendJoinAnswerAuthorization.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace
{

namespace cj = merovingian::canonicaljson;

auto const creator = std::string{"@creator:resident.example.org"};
auto const bob = std::string{"@bob:resident.example.org"};
auto const alice = std::string{"@alice:local.example.org"};

[[nodiscard]] auto parse(std::string const& raw) -> cj::Value
{
    auto const parsed = cj::parse_lossless(raw);
    REQUIRE(parsed.error == cj::ParseError::none);
    return parsed.value;
}

[[nodiscard]] auto id_list(std::vector<std::string> const& ids) -> std::string
{
    auto list = std::string{};
    for (auto const& id : ids)
    {
        list += list.empty() ? "\"" : ",\"";
        list += id;
        list += "\"";
    }
    return list;
}

// A room's events, built the way an honest resident builds them, with the room ID each version requires.
class RoomFixture final
{
public:
    explicit RoomFixture(std::string_view version)
        : policy_{*merovingian::rooms::find_room_version_policy(version)}
    {
        auto const content = std::string{R"({"room_version":")"} + std::string{version} +
                             (policy_.create_event_is_room_id ? "\"}" : R"(","creator":")" + creator + "\"}");
        auto create_json = std::string{R"({"type":"m.room.create","state_key":"","sender":")"} + creator +
                           R"(","depth":1,"origin_server_ts":900,"prev_events":[],"auth_events":[],"content":)" +
                           content;
        if (policy_.create_event_is_room_id)
        {
            create = parse(create_json + "}");
            create_id = id_of(create);
            room_id = "!" + create_id.substr(1U);
        }
        else
        {
            room_id = "!room:resident.example.org";
            create = parse(create_json + R"(,"room_id":")" + room_id + "\"}");
            create_id = id_of(create);
        }
        creator_join =
            event("m.room.member", creator, creator, R"({"membership":"join"})", with_create({}), {create_id});
        creator_join_id = id_of(creator_join);
        // Room version 12: a creator's power comes from the create event, and listing one in `users` is refused.
        power_levels = event("m.room.power_levels", "", creator,
                             policy_.create_event_is_room_id ? std::string{R"({"users":{}})"}
                                                             : R"({"users":{")" + creator + R"(":100}})",
                             with_create({creator_join_id}));
        power_levels_id = id_of(power_levels);
        join_rules = event("m.room.join_rules", "", creator, R"({"join_rule":"public"})",
                           with_create({creator_join_id, power_levels_id}));
        join_rules_id = id_of(join_rules);
        bob_join =
            event("m.room.member", bob, bob, R"({"membership":"join"})", with_create({power_levels_id, join_rules_id}));
        bob_join_id = id_of(bob_join);
    }

    [[nodiscard]] auto id_of(cj::Value const& value) const -> std::string
    {
        auto const id = merovingian::events::make_reference_hash_event_id(value, policy_);
        REQUIRE(id.error.empty());
        return id.event_id;
    }

    // The create event, named only where the version permits it (rooms/v12.md), then `ids`.
    [[nodiscard]] auto with_create(std::vector<std::string> const& ids) const -> std::vector<std::string>
    {
        auto named = std::vector<std::string>{};
        if (!policy_.create_event_is_room_id)
        {
            named.push_back(create_id);
        }
        named.insert(named.end(), ids.begin(), ids.end());
        return named;
    }

    [[nodiscard]] auto event(std::string const& type, std::string const& state_key, std::string const& sender,
                             std::string const& content, std::vector<std::string> const& auth,
                             std::vector<std::string> const& prev = {}) const -> cj::Value
    {
        return parse(std::string{R"({"type":")"} + type + R"(","state_key":")" + state_key + R"(","sender":")" +
                     sender + R"(","room_id":")" + room_id + R"(","depth":5,"origin_server_ts":950,"prev_events":[)" +
                     id_list(prev) + R"(],"auth_events":[)" + id_list(auth) + R"(],"content":)" + content + "}");
    }

    [[nodiscard]] auto alice_join() const -> cj::Value
    {
        return event("m.room.member", alice, alice, R"({"membership":"join"})",
                     with_create({power_levels_id, join_rules_id}));
    }

    [[nodiscard]] auto state() const -> cj::Array
    {
        return {create, creator_join, power_levels, join_rules, bob_join};
    }

    [[nodiscard]] auto judge(cj::Array const& state_array, cj::Array const& chain) const
        -> merovingian::homeserver::AuthorizedSendJoinAnswer
    {
        return merovingian::homeserver::authorize_send_join_answer(state_array, chain, alice_join(), policy_, room_id);
    }

    [[nodiscard]] auto holds(cj::Array const& entries, std::string const& event_id) const -> bool
    {
        return std::ranges::any_of(entries, [&](cj::Value const& entry) {
            return id_of(entry) == event_id;
        });
    }

    merovingian::rooms::RoomVersionPolicy policy_;
    std::string room_id{};
    cj::Value create{};
    std::string create_id{};
    cj::Value creator_join{};
    std::string creator_join_id{};
    cj::Value power_levels{};
    std::string power_levels_id{};
    cj::Value join_rules{};
    std::string join_rules_id{};
    cj::Value bob_join{};
    std::string bob_join_id{};
};

} // namespace

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 4; PUT /_matrix/federation/v2/send_join
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
SCENARIO("An honest send_join answer is kept whole, whatever order it lists its events in",
         "[f45][send_join][federation][conformance]")
{
    for (auto const* version : {"10", "11", "12"})
    {
        GIVEN(std::string{"a room of version "} + version + " and a resident answering truthfully")
        {
            auto const room = RoomFixture{version};

            WHEN("the answer lists each event before the events it names")
            {
                auto state = room.state();
                std::ranges::reverse(state);
                auto const answer = room.judge(state, room.state());

                THEN("every event is kept, in the order it arrived, and the join may go ahead")
                {
                    CAPTURE(answer.refusal);
                    REQUIRE(answer.refusal.empty());
                    REQUIRE(answer.dropped == 0U);
                    REQUIRE(answer.state.size() == state.size());
                    REQUIRE(room.id_of(answer.state.front()) == room.bob_join_id);
                    REQUIRE(answer.auth_chain.size() == state.size());
                }
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 4; PUT /_matrix/federation/v2/send_join
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
SCENARIO("A send_join answer's event that the auth rules refuse is dropped, not stored as room state",
         "[f45][send_join][federation][conformance]")
{
    GIVEN("a room where bob holds the default power level of 0")
    {
        auto const room = RoomFixture{"10"};
        // State events need power level 50 by default: Server-Server API, authorisation rules, "If the event type's
        // required power level is greater than the sender's power level, reject."
        auto const forged_power = room.event("m.room.power_levels", "", bob, R"({"users":{")" + bob + R"(":100}})",
                                             room.with_create({room.power_levels_id, room.bob_join_id}));

        WHEN("the resident lists a power levels event bob had no power to send")
        {
            auto state = room.state();
            state.push_back(forged_power);
            auto const answer = room.judge(state, {});

            THEN("that event is gone and everything else is kept")
            {
                REQUIRE(answer.refusal.empty());
                REQUIRE(answer.dropped == 1U);
                REQUIRE_FALSE(room.holds(answer.state, room.id_of(forged_power)));
                REQUIRE(room.holds(answer.state, room.power_levels_id));
                REQUIRE(room.holds(answer.state, room.bob_join_id));
            }
        }

        WHEN("an event names the refused event as its own authority")
        {
            auto const raised_id = room.id_of(forged_power);
            auto const topic = room.event("m.room.topic", "", bob, R"({"topic":"taken over"})",
                                          room.with_create({raised_id, room.bob_join_id}));
            auto state = room.state();
            state.push_back(topic);
            auto chain = cj::Array{forged_power};
            auto const answer = room.judge(state, chain);

            THEN("rule 2.3's reasoning holds: a refused event authorises nothing, so both are dropped")
            {
                REQUIRE(answer.refusal.empty());
                REQUIRE(answer.dropped == 2U);
                REQUIRE(answer.auth_chain.empty());
                REQUIRE_FALSE(room.holds(answer.state, room.id_of(topic)));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 4; PUT /_matrix/federation/v2/send_join
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
SCENARIO("A send_join answer's event must name auth events the answer holds, and a permitted selection of them",
         "[f45][send_join][federation][conformance]")
{
    GIVEN("a room whose resident lists one more event")
    {
        auto const room = RoomFixture{"10"};

        WHEN("the event names an auth event the answer does not hold")
        {
            auto const missing = room.event("m.room.topic", "", creator, R"({"topic":"x"})",
                                            room.with_create({"$absent", room.creator_join_id}));
            auto state = room.state();
            state.push_back(missing);
            auto const answer = room.judge(state, {});

            THEN("it is dropped: an authority that cannot be read authorises nothing")
            {
                REQUIRE(answer.refusal.empty());
                REQUIRE(answer.dropped == 1U);
                REQUIRE_FALSE(room.holds(answer.state, room.id_of(missing)));
            }
        }

        // Spec: "Auth events selection" lists what an event's auth_events may name. Another user's membership is not
        // on the list for a topic event, so naming it is rule 2.2's rejection whatever the event would otherwise pass.
        WHEN("the event names another user's membership event")
        {
            auto const overreaching =
                room.event("m.room.topic", "", creator, R"({"topic":"x"})",
                           room.with_create({room.power_levels_id, room.creator_join_id, room.bob_join_id}));
            auto state = room.state();
            state.push_back(overreaching);
            auto const answer = room.judge(state, {});

            THEN("it is dropped")
            {
                REQUIRE(answer.dropped == 1U);
                REQUIRE_FALSE(room.holds(answer.state, room.id_of(overreaching)));
            }
        }
    }

    // Spec: rooms/v12.md rule 3.2, "In this room version, m.room.create MUST NOT be selected".
    GIVEN("a version 12 room")
    {
        auto const room = RoomFixture{"12"};

        WHEN("an event names the create event in its auth_events")
        {
            auto const naming_create = room.event("m.room.topic", "", creator, R"({"topic":"x"})",
                                                  {room.create_id, room.power_levels_id, room.creator_join_id});
            auto state = room.state();
            state.push_back(naming_create);
            auto const answer = room.judge(state, {});

            THEN("it is dropped")
            {
                REQUIRE(answer.dropped == 1U);
                REQUIRE_FALSE(room.holds(answer.state, room.id_of(naming_create)));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 4; PUT /_matrix/federation/v2/send_join
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
SCENARIO("A join refuses an answer that cannot establish the room or authorise the join",
         "[f45][send_join][federation][conformance]")
{
    GIVEN("a version 10 room")
    {
        auto const room = RoomFixture{"10"};

        WHEN("the state holds no create event")
        {
            auto const answer = room.judge({room.power_levels, room.join_rules}, {});

            THEN("the join is refused")
            {
                REQUIRE_FALSE(answer.refusal.empty());
            }
        }

        WHEN("the create event appears only in the auth chain")
        {
            auto const answer = room.judge({room.creator_join, room.power_levels, room.join_rules}, {room.create});

            THEN("the join is refused: the create event is part of the room's state")
            {
                REQUIRE_FALSE(answer.refusal.empty());
            }
        }

        WHEN("the answer holds two create events for the room")
        {
            auto const second_create = room.event("m.room.create", "", creator,
                                                  R"({"room_version":"10","creator":")" + creator + R"(","x":1})", {});
            auto state = room.state();
            state.push_back(second_create);
            auto const answer = room.judge(state, {});

            THEN("the join is refused: a room has one create event")
            {
                REQUIRE_FALSE(answer.refusal.empty());
            }
        }

        WHEN("the join rules say invite and the answer holds no invite for the joining user")
        {
            auto const invite_only = room.event("m.room.join_rules", "", creator, R"({"join_rule":"invite"})",
                                                room.with_create({room.creator_join_id, room.power_levels_id}));
            auto const invite_only_id = room.id_of(invite_only);
            auto const join = room.event("m.room.member", alice, alice, R"({"membership":"join"})",
                                         room.with_create({room.power_levels_id, invite_only_id}));
            auto const answer = merovingian::homeserver::authorize_send_join_answer(
                {room.create, room.creator_join, room.power_levels, invite_only}, {}, join, room.policy_, room.room_id);

            THEN("the join is refused, though every event of the answer is valid")
            {
                REQUIRE(answer.dropped == 0U);
                REQUIRE_FALSE(answer.refusal.empty());
            }
        }

        WHEN("the join names an auth event the answer does not hold")
        {
            auto const join = room.event("m.room.member", alice, alice, R"({"membership":"join"})",
                                         room.with_create({room.power_levels_id, "$absent", room.join_rules_id}));
            auto const answer =
                merovingian::homeserver::authorize_send_join_answer(room.state(), {}, join, room.policy_, room.room_id);

            THEN("the join is refused")
            {
                REQUIRE_FALSE(answer.refusal.empty());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Checks performed on receipt of a PDU, step 4; PUT /_matrix/federation/v2/send_join
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#checks-performed-on-receipt-of-a-pdu
SCENARIO("A send_join answer's auth graph may be as deep as the resident likes without exhausting the stack",
         "[f45][send_join][federation][conformance]")
{
    GIVEN("a member whose display name changed many times, each change naming the one before")
    {
        auto const room = RoomFixture{"10"};
        static constexpr auto changes = std::size_t{20000U};
        auto chain = room.state();
        auto previous_id = room.bob_join_id;
        for (auto change = std::size_t{0U}; change < changes; ++change)
        {
            auto next = room.event("m.room.member", bob, bob,
                                   R"({"membership":"join","displayname":"bob )" + std::to_string(change) + R"("})",
                                   room.with_create({room.power_levels_id, room.join_rules_id, previous_id}));
            previous_id = room.id_of(next);
            chain.push_back(std::move(next));
        }

        WHEN("the answer lists the whole chain")
        {
            auto const answer = room.judge(room.state(), chain);

            THEN("every link is judged and kept")
            {
                REQUIRE(answer.refusal.empty());
                REQUIRE(answer.dropped == 0U);
                REQUIRE(answer.auth_chain.size() == chain.size());
            }
        }
    }
}
