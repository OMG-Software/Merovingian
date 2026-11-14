// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Security audit run 4, F-10 and F-12 (ADR-0591): what the resident answers to send_join, send_leave and send_knock.
//
//   * A server with no current local member in a room is not a resident of it: it stores nothing and answers
//     nothing for send_join, send_leave and send_knock (F-12).
//   * An event that auth rejects, or that soft-fails against the room's current state, is refused 403 and never
//     stored, so no row accumulates per origin and no state is given to a server whose user is not admitted (F-10,
//     F-12).
//   * An event already stored is answered again only while it is still the sender's current membership (F-10).
//
// Tags: [f10], [f12].

#include "../support/Genesis.hpp"
#include "../support/MembershipAcceptorFixture.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/MembershipAcceptResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::federation::FederationEndpoint;
using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::MembershipAcceptResult;
using merovingian::homeserver::HomeserverRuntime;
using merovingian::tests::membership_acceptor_fixture::build_event_json;
using merovingian::tests::membership_acceptor_fixture::config_with_sqlite;
using merovingian::tests::membership_acceptor_fixture::Genesis;
using merovingian::tests::membership_acceptor_fixture::make_envelope;
using merovingian::tests::membership_acceptor_fixture::seed_accepted_event;
using merovingian::tests::membership_acceptor_fixture::seed_room_genesis;
using merovingian::tests::membership_acceptor_fixture::unique_sqlite_path;

auto const bob = std::string{"@bob:remote.example.org"};
auto const local_admin = std::string{"@admin:local.example.org"};

// A runtime built in place and never moved: the federation callbacks capture its address.
class Fixture final
{
public:
    explicit Fixture(std::string const& room_id, std::string const& admin = local_admin)
        : path_{unique_sqlite_path()}
        , started_{start()}
        , room_id_{room_id}
    {
        REQUIRE(started_.started);
        merovingian::homeserver::wire_federation_callbacks(started_.runtime);
        genesis_ = seed_room_genesis(started_.runtime, room_id_, admin);
    }

    Fixture(Fixture const&) = delete;
    auto operator=(Fixture const&) -> Fixture& = delete;
    Fixture(Fixture&&) = delete;
    auto operator=(Fixture&&) -> Fixture& = delete;

    ~Fixture()
    {
        std::filesystem::remove(path_);
    }

    [[nodiscard]] auto runtime() -> HomeserverRuntime&
    {
        return started_.runtime;
    }
    [[nodiscard]] auto room_id() const -> std::string const&
    {
        return room_id_;
    }
    [[nodiscard]] auto genesis() const -> Genesis const&
    {
        return genesis_;
    }

    // The membership event of `sender`, built on `prev` and naming `auth` as its auth_events.
    [[nodiscard]] auto member_event(std::string const& event_id, std::string const& sender,
                                    std::string const& membership, std::vector<std::string> const& prev,
                                    std::vector<std::string> const& auth, std::int64_t depth) const
        -> InboundPduEnvelope
    {
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(
            merovingian::canonicaljson::make_member("membership", merovingian::canonicaljson::Value{membership}));
        auto const json = build_event_json(room_id_, "m.room.member", sender, sender, std::move(content), prev, auth,
                                           depth, depth + 1);
        return make_envelope(room_id_, event_id, "m.room.member", sender, sender, prev, auth, depth, json);
    }

    [[nodiscard]] auto accept(FederationEndpoint endpoint, InboundPduEnvelope const& envelope) -> MembershipAcceptResult
    {
        return started_.runtime.federation.membership_acceptor(endpoint, room_id_, envelope.event_id, envelope);
    }

    [[nodiscard]] auto event_stored(std::string const& event_id) -> bool
    {
        return std::ranges::any_of(started_.runtime.database.persistent_store.events,
                                   [&](merovingian::database::PersistentEvent const& event) {
                                       return event.event_id == event_id;
                                   });
    }

private:
    [[nodiscard]] auto start() -> merovingian::homeserver::RuntimeStartResult
    {
        std::filesystem::remove(path_);
        return merovingian::homeserver::start_runtime(config_with_sqlite(path_));
    }

    std::filesystem::path path_;
    merovingian::homeserver::RuntimeStartResult started_;
    std::string room_id_;
    Genesis genesis_{};
};

// Everything a membership request could change in the store.
struct StoreShape final
{
    std::size_t events{};
    std::size_t state{};
    std::size_t memberships{};
    std::size_t state_groups{};
    std::uint64_t next_stream_ordering{};
    std::uint64_t next_sync_stream_id{};

    [[nodiscard]] auto operator==(StoreShape const&) const -> bool = default;
};

[[nodiscard]] auto store_shape(HomeserverRuntime const& runtime) -> StoreShape
{
    auto const& store = runtime.database.persistent_store;
    return {store.events.size(),
            store.state.size(),
            store.memberships.size(),
            store.state_groups.size(),
            runtime.database.next_stream_ordering,
            store.next_sync_stream_id};
}

[[nodiscard]] auto join_auth(Genesis const& genesis) -> std::vector<std::string>
{
    return {genesis.create_id, genesis.pl_id, genesis.join_rules_id};
}

} // namespace

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}; "Joining Rooms"; "Rejection"; "Soft failure"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// send_join: "403: The room that the joining server is attempting to join does not permit the user to join." A
// join the room's current state does not permit, or one the user no longer has as their membership, is refused and
// carries no room state. This server refuses the request, so it never takes the event into its DAG.
SCENARIO("A send_join is answered with state only while it is the joiner's current, accepted membership",
         "[federation][conformance][membership][f10]")
{
    GIVEN("a public room, and a remote user whose join was accepted and who then left")
    {
        auto fixture = Fixture{"!f10leave:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const join_id = std::string{"$f10join:remote.example.org"};
        auto const join = fixture.member_event(join_id, bob, "join", {genesis.join_rules_id}, join_auth(genesis), 4);
        auto const first = fixture.accept(FederationEndpoint::send_join, join);
        REQUIRE(first.accepted);
        auto const leave_id = std::string{"$f10leave:remote.example.org"};
        auto const leave =
            fixture.member_event(leave_id, bob, "leave", {join_id}, {genesis.create_id, genesis.pl_id, join_id}, 5);
        REQUIRE(fixture.accept(FederationEndpoint::send_leave, leave).accepted);
        auto const before = store_shape(fixture.runtime());

        WHEN("their server sends the old join again")
        {
            auto const second = fixture.accept(FederationEndpoint::send_join, join);

            THEN("it is refused with 403 and the body holds no room state")
            {
                // Spec MUST: 403 when the room "does not permit the user to join".
                REQUIRE_FALSE(second.accepted);
                REQUIRE(second.status == 403U);
                // Spec MUST NOT: give the room's state to a server whose user is not joined.
                REQUIRE(second.state_json.empty());
                REQUIRE(second.auth_chain_json.empty());
                REQUIRE(second.signed_event_json.empty());
            }
            AND_THEN("nothing is stored")
            {
                // Spec: a refused request leaves no event of its own behind.
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }

    GIVEN("a public room in which a remote user is banned, and a join that cites the history from before the ban")
    {
        auto fixture = Fixture{"!f10ban:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const ban_id = fixture.room_id() + ":ban-bob";
        // The ban is sent by the room's admin.
        auto ban_content = merovingian::canonicaljson::Object{};
        ban_content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"ban"}}));
        auto const ban_json = build_event_json(fixture.room_id(), "m.room.member", bob, local_admin,
                                               std::move(ban_content), {genesis.join_rules_id},
                                               {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 4, 5);
        seed_accepted_event(fixture.runtime(), fixture.room_id(), ban_id, "m.room.member", bob, local_admin, ban_json,
                            {genesis.join_rules_id}, 4U);
        auto const soft_id = std::string{"$f10soft:remote.example.org"};
        auto const soft = fixture.member_event(soft_id, bob, "join", {genesis.join_rules_id}, join_auth(genesis), 4);
        auto const before = store_shape(fixture.runtime());

        WHEN("the banned user's server sends that join")
        {
            auto const result = fixture.accept(FederationEndpoint::send_join, soft);

            THEN("it is refused with 403 and the body holds no room state")
            {
                // Spec MUST: 403 when the room "does not permit the user to join".
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
                // Spec MUST NOT: reveal the room's state to a server whose user is banned.
                REQUIRE(result.state_json.empty());
                REQUIRE(result.auth_chain_json.empty());
            }
            AND_THEN("the join is not stored")
            {
                // Spec: the soft-failed join is not taken into the DAG; the 403 tells the sender so.
                REQUIRE_FALSE(fixture.event_stored(soft_id));
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }

    GIVEN("a public room and a remote user whose accepted join is still their current membership")
    {
        auto fixture = Fixture{"!f10retry:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const join_id = std::string{"$f10retry:remote.example.org"};
        auto const join = fixture.member_event(join_id, bob, "join", {genesis.join_rules_id}, join_auth(genesis), 4);
        auto const first = fixture.accept(FederationEndpoint::send_join, join);
        REQUIRE(first.accepted);

        WHEN("their server sends the join again, having lost the first answer")
        {
            auto const second = fixture.accept(FederationEndpoint::send_join, join);

            THEN("it is answered 200 with the same state and the stored event")
            {
                // Spec MUST: 200 when "The join event has been accepted into the room."
                REQUIRE(second.accepted);
                REQUIRE(second.status == 200U);
                REQUIRE_FALSE(second.state_json.empty());
                REQUIRE(second.state_json.size() == first.state_json.size());
                REQUIRE(second.signed_event_json == first.signed_event_json);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}; "Knocking upon a room"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv1send_knockroomideventid
//
// send_knock: "403: The knocking server or user is not permitted to knock on the room, such as when the
// server/user is banned". A knock that soft-fails against current state is refused and carries no stripped state.
SCENARIO("A send_knock that soft-fails is refused 403 with no room state and is not stored",
         "[federation][conformance][membership][f10]")
{
    GIVEN("a knock room in which a remote user is banned, and a knock citing the history from before the ban")
    {
        auto fixture = Fixture{"!f10knock:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const rules_id = fixture.room_id() + ":knock-rules";
        auto rules_content = merovingian::canonicaljson::Object{};
        rules_content.push_back(merovingian::canonicaljson::make_member(
            "join_rule", merovingian::canonicaljson::Value{std::string{"knock"}}));
        auto const rules_json = build_event_json(fixture.room_id(), "m.room.join_rules", std::string{}, local_admin,
                                                 std::move(rules_content), {genesis.join_rules_id},
                                                 {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 4, 5);
        seed_accepted_event(fixture.runtime(), fixture.room_id(), rules_id, "m.room.join_rules", std::string{},
                            local_admin, rules_json, {genesis.join_rules_id}, 4U);
        auto const ban_id = fixture.room_id() + ":ban-bob";
        auto ban_content = merovingian::canonicaljson::Object{};
        ban_content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"ban"}}));
        auto const ban_json =
            build_event_json(fixture.room_id(), "m.room.member", bob, local_admin, std::move(ban_content), {rules_id},
                             {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 5, 6);
        seed_accepted_event(fixture.runtime(), fixture.room_id(), ban_id, "m.room.member", bob, local_admin, ban_json,
                            {rules_id}, 5U);
        auto const knock_id = std::string{"$f10knock:remote.example.org"};
        auto const knock =
            fixture.member_event(knock_id, bob, "knock", {rules_id}, {genesis.create_id, genesis.pl_id, rules_id}, 5);
        auto const before = store_shape(fixture.runtime());

        WHEN("the banned user's server sends the knock")
        {
            auto const result = fixture.accept(FederationEndpoint::send_knock, knock);

            THEN("it is refused with 403 and there is no knock_room_state")
            {
                // Spec MUST: 403 when "the server/user is banned".
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
                // Spec MUST NOT: give stripped room state to a user who may not knock.
                REQUIRE(result.knock_room_state_json.empty());
            }
            AND_THEN("the knock is not stored")
            {
                // Spec: the soft-failed knock is not taken into the DAG; the 403 tells the sender so.
                REQUIRE_FALSE(fixture.event_stored(knock_id));
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv1send_knockroomideventid
//
// send_knock: "servers SHOULD return M_INVALID_PARAM if ... The membership field inside the event content is not
// knock." The check runs before an already stored event is answered again, on main's side of a worker relay too: a
// relay carries no URL event ID, and a worker frame is untrusted (ADR-0071).
SCENARIO("A stored leave relayed as send_knock is refused before it is answered as a resend",
         "[federation][conformance][membership][f10]")
{
    GIVEN("a public room, and a remote user whose accepted leave is their current membership")
    {
        auto fixture = Fixture{"!f10relay:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const join_id = std::string{"$f10relayjoin:remote.example.org"};
        auto const join = fixture.member_event(join_id, bob, "join", {genesis.join_rules_id}, join_auth(genesis), 4);
        REQUIRE(fixture.accept(FederationEndpoint::send_join, join).accepted);
        auto const leave_id = std::string{"$f10relayleave:remote.example.org"};
        auto leave =
            fixture.member_event(leave_id, bob, "leave", {join_id}, {genesis.create_id, genesis.pl_id, join_id}, 5);
        REQUIRE(fixture.accept(FederationEndpoint::send_leave, leave).accepted);
        leave.origin = "remote.example.org";
        auto const before = store_shape(fixture.runtime());

        WHEN("a worker relays that leave to main as a send_knock")
        {
            auto const result = fixture.runtime().federation.membership_acceptor(FederationEndpoint::send_knock,
                                                                                 fixture.room_id(), {}, leave);

            THEN("it is refused 400 M_INVALID_PARAM with no knock_room_state")
            {
                // Spec SHOULD: M_INVALID_PARAM when "The membership field inside the event content is not knock".
                REQUIRE_FALSE(result.accepted);
                // Spec SHOULD: the refusal is a 400, not a resend answer.
                REQUIRE(result.status == 400U);
                // Spec SHOULD: the errcode is M_INVALID_PARAM.
                REQUIRE(result.reason.find("M_INVALID_PARAM") != std::string::npos);
                // Spec MUST NOT: answer a request that is not a knock with the room's stripped state.
                REQUIRE(result.knock_room_state_json.empty());
                // Spec MUST NOT: send the stored event back as if the knock had been accepted.
                REQUIRE(result.signed_event_json.empty());
            }
            AND_THEN("nothing is stored")
            {
                // Spec: a refused request leaves nothing behind.
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}; PUT /_matrix/federation/v1/send_knock/...
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_leaveroomideventid
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv1send_knockroomideventid
//
// send_leave: "200: An empty response to indicate the event was accepted into the graph by the receiving
// homeserver." send_knock: "200: Information about the room to pass along to clients regarding the knock." A
// sending server that lost the first answer retries; while the event is still the sender's accepted membership it is
// answered again, and is not stored a second time.
SCENARIO("A resent leave or knock that is still the sender's membership is answered again and not stored twice",
         "[federation][conformance][membership][f10]")
{
    GIVEN("a public room and a remote user whose accepted leave is their current membership")
    {
        auto fixture = Fixture{"!f10leaveretry:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const join_id = std::string{"$f10leaveretryjoin:remote.example.org"};
        auto const join = fixture.member_event(join_id, bob, "join", {genesis.join_rules_id}, join_auth(genesis), 4);
        REQUIRE(fixture.accept(FederationEndpoint::send_join, join).accepted);
        auto const leave_id = std::string{"$f10leaveretry:remote.example.org"};
        auto const leave =
            fixture.member_event(leave_id, bob, "leave", {join_id}, {genesis.create_id, genesis.pl_id, join_id}, 5);
        REQUIRE(fixture.accept(FederationEndpoint::send_leave, leave).accepted);
        auto const before = store_shape(fixture.runtime());

        WHEN("their server sends the leave again")
        {
            auto const second = fixture.accept(FederationEndpoint::send_leave, leave);

            THEN("it is answered 200 with the stored event, and nothing is stored")
            {
                // Spec MUST: 200 when the event "was accepted into the graph".
                REQUIRE(second.accepted);
                // Spec MUST: the status of an accepted leave is 200.
                REQUIRE(second.status == 200U);
                // Spec: the answer is about the event already in the graph, the one the sender sent.
                REQUIRE_FALSE(second.signed_event_json.empty());
                // Spec: a retry does not take the event into the graph a second time.
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }

    GIVEN("a knock room and a remote user whose accepted knock is their current membership")
    {
        auto fixture = Fixture{"!f10knockretry:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const rules_id = fixture.room_id() + ":knock-rules";
        auto rules_content = merovingian::canonicaljson::Object{};
        rules_content.push_back(merovingian::canonicaljson::make_member(
            "join_rule", merovingian::canonicaljson::Value{std::string{"knock"}}));
        auto const rules_json = build_event_json(fixture.room_id(), "m.room.join_rules", std::string{}, local_admin,
                                                 std::move(rules_content), {genesis.join_rules_id},
                                                 {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 4, 5);
        seed_accepted_event(fixture.runtime(), fixture.room_id(), rules_id, "m.room.join_rules", std::string{},
                            local_admin, rules_json, {genesis.join_rules_id}, 4U);
        auto const knock_id = std::string{"$f10knockretry:remote.example.org"};
        auto const knock =
            fixture.member_event(knock_id, bob, "knock", {rules_id}, {genesis.create_id, genesis.pl_id, rules_id}, 5);
        auto const first = fixture.accept(FederationEndpoint::send_knock, knock);
        REQUIRE(first.accepted);
        auto const before = store_shape(fixture.runtime());

        WHEN("their server sends the knock again")
        {
            auto const second = fixture.accept(FederationEndpoint::send_knock, knock);

            THEN("it is answered 200 with knock_room_state, and nothing is stored")
            {
                // Spec MUST: 200 with "Information about the room to pass along to clients regarding the knock".
                REQUIRE(second.accepted);
                // Spec MUST: the status of an accepted knock is 200.
                REQUIRE(second.status == 200U);
                // Spec MUST: knock_room_state is part of the answer.
                REQUIRE_FALSE(second.knock_room_state_json.empty());
                // Spec: a retry does not take the event into the graph a second time.
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}; "Joining Rooms"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// "The receiving server MUST apply certain validation before accepting the event. A specific error code is not
// mandated, but servers SHOULD return M_INVALID_PARAM if: ... The event type is not m.room.member. The membership
// field inside the event content is not join. The event sender is not a user ID on the origin server. The state_key
// is not equal to the sender." The acceptor also holds the event to the room and event ID the request names. Each
// is refused before anything is stored or any stored event is answered again.
SCENARIO("A membership event that does not match its endpoint, path or origin is refused 400 M_INVALID_PARAM",
         "[federation][conformance][membership][f10]")
{
    GIVEN("a public room with a local member and a well-formed join from a remote user")
    {
        auto fixture = Fixture{"!f10agree:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const join_id = std::string{"$f10agree:remote.example.org"};
        auto const join = fixture.member_event(join_id, bob, "join", {genesis.join_rules_id}, join_auth(genesis), 4);
        auto const leave = fixture.member_event(join_id, bob, "leave", {genesis.join_rules_id}, join_auth(genesis), 4);

        struct Case final
        {
            std::string name;
            FederationEndpoint endpoint;
            std::string event_id;
            InboundPduEnvelope envelope;
        };
        auto cases = std::vector<Case>{};
        cases.push_back({"a leave sent to send_join", FederationEndpoint::send_join, join_id, leave});
        cases.push_back({"an endpoint that is not send_*", FederationEndpoint::transaction, join_id, join});
        auto not_member = join;
        not_member.event_type = "m.room.topic";
        cases.push_back({"an event type other than m.room.member", FederationEndpoint::send_join, join_id, not_member});
        auto other_target = join;
        other_target.state_key = std::string{"@carol:remote.example.org"};
        cases.push_back({"a state_key other than the sender", FederationEndpoint::send_join, join_id, other_target});
        auto no_target = join;
        no_target.state_key.reset();
        cases.push_back({"no state_key", FederationEndpoint::send_join, join_id, no_target});
        auto other_room = join;
        other_room.room_id = "!elsewhere:local.example.org";
        cases.push_back({"another room than the path's", FederationEndpoint::send_join, join_id, other_room});
        cases.push_back(
            {"another event ID than the path's", FederationEndpoint::send_join, "$other:remote.example.org", join});
        auto other_origin = join;
        other_origin.origin = "other.example.org";
        cases.push_back({"a sender not on the origin", FederationEndpoint::send_join, join_id, other_origin});
        auto unparsable = join;
        unparsable.json = "{";
        cases.push_back({"a body that is not JSON", FederationEndpoint::send_join, join_id, unparsable});
        auto const before = store_shape(fixture.runtime());

        WHEN("each is sent")
        {
            auto results = std::vector<MembershipAcceptResult>{};
            for (auto const& c : cases)
            {
                results.push_back(fixture.runtime().federation.membership_acceptor(c.endpoint, fixture.room_id(),
                                                                                   c.event_id, c.envelope));
            }

            THEN("each is refused 400 and nothing is stored")
            {
                for (auto i = std::size_t{0U}; i < cases.size(); ++i)
                {
                    CAPTURE(cases[i].name);
                    // Spec SHOULD: the receiving server refuses the event (M_INVALID_PARAM).
                    REQUIRE_FALSE(results[i].accepted);
                    // Spec SHOULD: the refusal is a 400.
                    REQUIRE(results[i].status == 400U);
                    // Spec MUST NOT: a refused join is answered with no room state.
                    REQUIRE(results[i].state_json.empty());
                }
                // Spec: a refused request leaves nothing behind.
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: PUT send_join, send_leave, send_knock; "Rejection"; "Soft failure"
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms
//
// A server with no local member in a room is not a resident of it: it cannot answer a join with the room's state,
// or accept a leave or knock into a DAG it is not part of. send_knock lists 404 for "the room ... is unknown to the
// receiving server"; send_join and send_leave list no code for this case, so 403 M_FORBIDDEN.
SCENARIO("send_join, send_leave and send_knock for a room with no local member store and answer nothing",
         "[federation][conformance][membership][f12]")
{
    GIVEN("a room this server holds, in which only a remote user is joined")
    {
        auto fixture = Fixture{"!f12none:local.example.org", "@admin:remote.example.org"};
        auto const& genesis = fixture.genesis();
        auto const before = store_shape(fixture.runtime());

        WHEN("a stranger's server sends a send_join, a send_leave and a send_knock")
        {
            auto const join = fixture.member_event("$f12join:other.example.net", "@eve:other.example.net", "join",
                                                   {genesis.join_rules_id}, join_auth(genesis), 4);
            auto const leave = fixture.member_event("$f12leave:other.example.net", "@eve:other.example.net", "leave",
                                                    {genesis.join_rules_id}, {genesis.create_id, genesis.pl_id}, 4);
            auto const knock = fixture.member_event("$f12knock:other.example.net", "@eve:other.example.net", "knock",
                                                    {genesis.join_rules_id}, join_auth(genesis), 4);
            auto const join_result = fixture.accept(FederationEndpoint::send_join, join);
            auto const leave_result = fixture.accept(FederationEndpoint::send_leave, leave);
            auto const knock_result = fixture.accept(FederationEndpoint::send_knock, knock);

            THEN("each is refused, with the code the spec lists for the case or 403")
            {
                // Spec MUST: send_join and send_leave list no code for a room the server is not in: 403 M_FORBIDDEN.
                REQUIRE_FALSE(join_result.accepted);
                REQUIRE(join_result.status == 403U);
                REQUIRE_FALSE(leave_result.accepted);
                REQUIRE(leave_result.status == 403U);
                // Spec MUST: 404 when the room is "unknown to the receiving server".
                REQUIRE_FALSE(knock_result.accepted);
                REQUIRE(knock_result.status == 404U);
                // Spec MUST NOT: send state to a server this server is not the resident for.
                REQUIRE(join_result.state_json.empty());
                REQUIRE(knock_result.knock_room_state_json.empty());
            }
            AND_THEN("the store is unchanged: no event, no current state, no stream ordering")
            {
                // Spec: a refused request is not taken into the DAG.
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }

    GIVEN("a room with a local member, and many stranger leaves that the auth rules deny")
    {
        auto fixture = Fixture{"!f12leaves:local.example.org"};
        auto const& genesis = fixture.genesis();
        auto const before = store_shape(fixture.runtime());

        WHEN("each leave is sent")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto index = 0; index < 5; ++index)
            {
                auto const user = "@eve" + std::to_string(index) + ":other.example.net";
                auto const event_id = "$f12denied" + std::to_string(index) + ":other.example.net";
                auto const leave = fixture.member_event(event_id, user, "leave", {genesis.join_rules_id},
                                                        {genesis.create_id, genesis.pl_id}, 4);
                statuses.push_back(fixture.accept(FederationEndpoint::send_leave, leave).status);
            }

            THEN("each is refused 403 and leaves no stored row")
            {
                // Spec: a rejected event is not taken into the DAG when the request is refused.
                REQUIRE(statuses == std::vector<std::uint16_t>(5U, std::uint16_t{403U}));
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: "Leaving Rooms (Rejecting Invites)"; PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#leaving-rooms-rejecting-invites
//
// A leave is sent to "a resident server", which "may be the server which sent the invite", and send_leave lists no
// refusal for a room whose last member of the receiving server has left. A remote user this server holds as joined,
// invited or knocking can therefore still leave through it (ADR-0747). Each such membership admits one stored leave:
// the leave ends it, and a stranger is refused as before (F-12).
SCENARIO("A remote member can leave through a server whose last local member has left",
         "[federation][conformance][membership][f12][adr0747]")
{
    GIVEN("a room this server holds with no local member, in which a remote user is joined")
    {
        auto fixture = Fixture{"!adr0747:local.example.org", "@admin:remote.example.org"};
        auto const& genesis = fixture.genesis();
        auto const join_id = std::string{"$adr0747join:remote.example.org"};
        auto const join = fixture.member_event(join_id, bob, "join", {genesis.join_rules_id}, join_auth(genesis), 4);
        seed_accepted_event(fixture.runtime(), fixture.room_id(), join_id, "m.room.member", bob, bob, join.json,
                            {genesis.join_rules_id}, 4U);
        auto const leave_auth = std::vector<std::string>{genesis.create_id, genesis.pl_id, join_id};

        WHEN("the joined user's server sends their leave, and then another leave for them")
        {
            auto const leave_id = std::string{"$adr0747leave:remote.example.org"};
            auto const leave = fixture.member_event(leave_id, bob, "leave", {join_id}, leave_auth, 5);
            auto const first = fixture.accept(FederationEndpoint::send_leave, leave);
            auto const after_first = store_shape(fixture.runtime());
            auto const again =
                fixture.member_event("$adr0747again:remote.example.org", bob, "leave", {join_id}, leave_auth, 6);
            auto const second = fixture.accept(FederationEndpoint::send_leave, again);

            THEN("the leave is accepted and stored, and the next one is refused with nothing stored")
            {
                // Spec MUST: 200 when the leave "was accepted into the graph".
                CAPTURE(first.reason);
                REQUIRE(first.accepted);
                REQUIRE(first.status == 200U);
                REQUIRE(fixture.event_stored(leave_id));
                // Spec: the leave ends the membership; the row no longer admits a leave.
                REQUIRE_FALSE(second.accepted);
                REQUIRE(second.status == 403U);
                REQUIRE(store_shape(fixture.runtime()) == after_first);
            }
        }

        WHEN("a user this server holds no membership for sends a leave, and a send_join and send_knock arrive")
        {
            auto const before = store_shape(fixture.runtime());
            auto const stranger =
                fixture.member_event("$adr0747stranger:other.example.net", "@eve:other.example.net", "leave",
                                     {genesis.join_rules_id}, {genesis.create_id, genesis.pl_id}, 5);
            auto const rejoin = fixture.member_event("$adr0747rejoin:remote.example.org", bob, "join", {join_id},
                                                     join_auth(genesis), 5);
            auto const leave_result = fixture.accept(FederationEndpoint::send_leave, stranger);
            auto const join_result = fixture.accept(FederationEndpoint::send_join, rejoin);

            THEN("each is refused 403 and nothing is stored")
            {
                // Spec MUST: send_leave and send_join list no code for a room the server is not in: 403.
                REQUIRE_FALSE(leave_result.accepted);
                REQUIRE(leave_result.status == 403U);
                REQUIRE_FALSE(join_result.accepted);
                REQUIRE(join_result.status == 403U);
                REQUIRE(join_result.state_json.empty());
                REQUIRE(store_shape(fixture.runtime()) == before);
            }
        }
    }
}
