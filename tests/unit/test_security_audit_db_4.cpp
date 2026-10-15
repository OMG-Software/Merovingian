// SPDX-License-Identifier: GPL-3.0-or-later

// DB-4 (29 Sep 2026 audit): the membership row commits with its m.room.member
// event, and reconcile_memberships_with_current_state makes the rows agree with
// current state at startup. Matrix v1.19 CS API "m.room.member": the room's
// current m.room.member event is the user's membership.

#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

using merovingian::database::MembershipProjection;
using merovingian::database::PersistentEvent;
using merovingian::database::PersistentInvite;
using merovingian::database::PersistentMembership;
using merovingian::database::PersistentStateEvent;
using merovingian::database::PersistentStore;

constexpr auto room_id = std::string_view{"!db4:example.org"};

[[nodiscard]] auto open_store() -> PersistentStore
{
    auto opened = merovingian::database::open_persistent_store();
    REQUIRE(opened.ok);
    return std::move(opened.store);
}

[[nodiscard]] auto member_event(std::string_view event_id, std::string_view user_id, std::string_view membership,
                                std::uint64_t stream_ordering) -> PersistentEvent
{
    auto event = PersistentEvent{};
    event.event_id = std::string{event_id};
    event.room_id = std::string{room_id};
    event.sender_user_id = "@alice:example.org";
    event.json = R"({"content":{"membership":")" + std::string{membership} + R"("},"event_id":")" +
                 std::string{event_id} + R"(","room_id":")" + std::string{room_id} +
                 R"(","sender":"@alice:example.org","state_key":")" + std::string{user_id} +
                 R"(","type":"m.room.member"})";
    event.depth = stream_ordering;
    event.stream_ordering = stream_ordering;
    return event;
}

[[nodiscard]] auto member_state(std::string_view event_id, std::string_view user_id) -> PersistentStateEvent
{
    return {std::string{room_id}, "m.room.member", std::string{user_id}, std::string{event_id}};
}

// Stores a member event as current state without touching its membership row,
// which is what a fault between the two writes used to leave behind.
auto store_current_member_event(PersistentStore& store, std::string_view event_id, std::string_view user_id,
                                std::string_view membership, std::uint64_t stream_ordering) -> void
{
    REQUIRE(merovingian::database::store_event_with_state(
        store, member_event(event_id, user_id, membership, stream_ordering), member_state(event_id, user_id)));
}

auto store_row(PersistentStore& store, std::string_view user_id, std::string_view membership,
               std::uint64_t stream_ordering) -> void
{
    REQUIRE(merovingian::database::store_membership(
                store, {std::string{room_id}, std::string{user_id}, std::string{membership}, stream_ordering}) ==
            merovingian::database::MembershipStoreResult::stored);
}

[[nodiscard]] auto row_of(PersistentStore const& store, std::string_view user_id) -> std::optional<PersistentMembership>
{
    auto const row = std::ranges::find_if(store.memberships, [user_id](PersistentMembership const& membership) {
        return membership.room_id == room_id && membership.user_id == user_id;
    });
    return row == store.memberships.end() ? std::nullopt : std::optional<PersistentMembership>{*row};
}

[[nodiscard]] auto has_invite(PersistentStore const& store, std::string_view user_id) -> bool
{
    return merovingian::database::find_invite(store, room_id, user_id).has_value();
}

[[nodiscard]] auto reconcile(PersistentStore& store, std::uint64_t& next_stream_ordering) -> std::size_t
{
    return merovingian::database::reconcile_memberships_with_current_state(store, [&next_stream_ordering] {
        return next_stream_ordering++;
    });
}

} // namespace

SCENARIO("DB-4 startup reconciliation makes membership rows agree with current state", "[db4][database]")
{
    GIVEN("a ban that is current state while bob's row, older than the ban, still says join")
    {
        auto store = open_store();
        store_current_member_event(store, "$bob-ban", "@bob:example.org", "ban", 5U);
        store_row(store, "@bob:example.org", "join", 3U);
        auto next = std::uint64_t{100U};

        WHEN("the rows are reconciled")
        {
            auto const corrected = reconcile(store, next);

            THEN("bob's row says ban at a fresh stream position")
            {
                CHECK(corrected == 1U);
                auto const row = row_of(store, "@bob:example.org");
                REQUIRE(row.has_value());
                CHECK(row->membership == "ban");
                CHECK(row->stream_ordering == 100U);
            }
        }
    }

    GIVEN("a row saying join that is newer than the leave event that is current state")
    {
        auto store = open_store();
        store_current_member_event(store, "$bob-leave", "@bob:example.org", "leave", 5U);
        store_row(store, "@bob:example.org", "join", 9U);
        auto next = std::uint64_t{100U};

        WHEN("the rows are reconciled")
        {
            auto const corrected = reconcile(store, next);

            THEN("the row still never grants more than current state: it says leave")
            {
                CHECK(corrected == 1U);
                CHECK(row_of(store, "@bob:example.org")->membership == "leave");
            }
        }
    }

    GIVEN("rows newer than their current member events that say leave or invite")
    {
        // A federated leave and an invite received over /invite are recorded
        // here before the event that carries them reaches current state.
        auto store = open_store();
        store_current_member_event(store, "$bob-join", "@bob:example.org", "join", 5U);
        store_row(store, "@bob:example.org", "leave", 9U);
        store_current_member_event(store, "$carol-leave", "@carol:example.org", "leave", 6U);
        store_row(store, "@carol:example.org", "invite", 10U);
        auto next = std::uint64_t{100U};

        WHEN("the rows are reconciled")
        {
            auto const corrected = reconcile(store, next);

            THEN("both rows are kept")
            {
                CHECK(corrected == 0U);
                CHECK(row_of(store, "@bob:example.org")->membership == "leave");
                CHECK(row_of(store, "@carol:example.org")->membership == "invite");
                CHECK(next == 100U);
            }
        }
    }

    GIVEN("an older invite row with invite metadata, and a ban that is current state")
    {
        auto store = open_store();
        store_current_member_event(store, "$dave-ban", "@dave:example.org", "ban", 8U);
        store_row(store, "@dave:example.org", "invite", 4U);
        REQUIRE(merovingian::database::upsert_invite(
            store, PersistentInvite{
                       std::string{room_id}, "@dave:example.org", "@alice:example.org", "$dave-invite", "{}", {}, 4U}));
        auto next = std::uint64_t{100U};

        WHEN("the rows are reconciled")
        {
            std::ignore = reconcile(store, next);

            THEN("the row says ban and the invite is gone")
            {
                CHECK(row_of(store, "@dave:example.org")->membership == "ban");
                CHECK_FALSE(has_invite(store, "@dave:example.org"));
            }
        }
    }

    GIVEN("a join that is current state for a user with no row")
    {
        auto store = open_store();
        store_current_member_event(store, "$erin-join", "@erin:example.org", "join", 7U);
        auto next = std::uint64_t{100U};

        WHEN("the rows are reconciled")
        {
            auto const corrected = reconcile(store, next);

            THEN("the row is created from current state")
            {
                CHECK(corrected == 1U);
                CHECK(row_of(store, "@erin:example.org")->membership == "join");
            }
        }
    }
}

SCENARIO("DB-4 a membership row commits with its member event or not at all", "[db4][database]")
{
    GIVEN("bob joined, on a store whose next membership write fails")
    {
        auto store = open_store();
        REQUIRE(merovingian::database::store_event_with_state(
            store, member_event("$bob-join", "@bob:example.org", "join", 2U),
            member_state("$bob-join", "@bob:example.org"),
            MembershipProjection{"@bob:example.org", "join", 3U, std::nullopt}));
        merovingian::database::force_persist_failure_for_statement(store, "upsert_membership");

        WHEN("a ban is stored with its membership projection")
        {
            auto const stored = merovingian::database::store_event_with_state(
                store, member_event("$bob-ban", "@bob:example.org", "ban", 4U),
                member_state("$bob-ban", "@bob:example.org"),
                MembershipProjection{"@bob:example.org", "ban", 5U, std::nullopt});

            THEN("nothing of the ban is stored: no event, no current state, no row change")
            {
                CHECK_FALSE(stored);
                CHECK_FALSE(std::ranges::any_of(store.events, [](PersistentEvent const& event) {
                    return event.event_id == "$bob-ban";
                }));
                auto const state = std::ranges::find_if(store.state, [](PersistentStateEvent const& entry) {
                    return entry.event_type == "m.room.member" && entry.state_key == "@bob:example.org";
                });
                REQUIRE(state != store.state.end());
                CHECK(state->event_id == "$bob-join");
                CHECK(row_of(store, "@bob:example.org")->membership == "join");
            }
        }
    }

    GIVEN("an invite stored with its invite metadata")
    {
        auto store = open_store();
        auto invite = PersistentInvite{
            std::string{room_id}, "@bob:example.org", "@alice:example.org", "$bob-invite", "{}", {}, 3U};
        REQUIRE(merovingian::database::store_event_with_state(
            store, member_event("$bob-invite", "@bob:example.org", "invite", 2U),
            member_state("$bob-invite", "@bob:example.org"),
            MembershipProjection{"@bob:example.org", "invite", 3U, invite}));
        REQUIRE(has_invite(store, "@bob:example.org"));

        WHEN("bob's join is stored with its membership projection")
        {
            REQUIRE(merovingian::database::store_event_with_state(
                store, member_event("$bob-join", "@bob:example.org", "join", 4U),
                member_state("$bob-join", "@bob:example.org"),
                MembershipProjection{"@bob:example.org", "join", 5U, std::nullopt}));

            THEN("the row says join and the invite is gone")
            {
                CHECK(row_of(store, "@bob:example.org")->membership == "join");
                CHECK(row_of(store, "@bob:example.org")->stream_ordering == 5U);
                CHECK_FALSE(has_invite(store, "@bob:example.org"));
            }
        }
    }

    GIVEN("a member event for bob")
    {
        auto store = open_store();

        WHEN("it is stored with a projection that names another user")
        {
            auto const stored = merovingian::database::store_event_with_state(
                store, member_event("$bob-join", "@bob:example.org", "join", 2U),
                member_state("$bob-join", "@bob:example.org"),
                MembershipProjection{"@mallory:example.org", "join", 3U, std::nullopt});

            THEN("nothing is stored")
            {
                CHECK_FALSE(stored);
                CHECK(store.events.empty());
                CHECK(store.memberships.empty());
            }
        }
    }
}
