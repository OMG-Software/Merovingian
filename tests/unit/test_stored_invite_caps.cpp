// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, unbounded stored invites per local user (ADR-0619).
//
// Spec: server-server-api.md, PUT /_matrix/federation/v2/invite: 403 M_FORBIDDEN, "The sender is not allowed to send
// invites to the target user/homeserver". The spec states no limit; the bounds are ADR-0619 decisions.

#include "merovingian/database/MembershipProjection.hpp"
#include "merovingian/database/PersistentInvite.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace
{

namespace db = merovingian::database;

constexpr auto victim = std::string_view{"@victim:home.example"};

[[nodiscard]] auto invite_from(std::string_view sender, std::string_view room, std::size_t event_bytes = 2U,
                               std::string_view user = victim) -> db::PersistentInvite
{
    return {std::string{room},
            std::string{user},
            std::string{sender},
            "$" + std::string{room},
            std::string(event_bytes, 'x'),
            {},
            1U};
}

[[nodiscard]] auto store_invite(db::PersistentStore& store, db::PersistentInvite invite) -> bool
{
    auto const room = invite.room_id;
    auto const user = invite.user_id;
    return db::store_membership_projection(store, room, {user, "invite", 1U, std::move(invite)});
}

[[nodiscard]] auto room_number(std::size_t number) -> std::string
{
    return "!room" + std::to_string(number) + ":remote.example";
}

// Stores `invites` invites for the victim, spread over `origins` servers.
auto fill_from_origins(db::PersistentStore& store, std::size_t invites, std::size_t origins) -> void
{
    for (auto number = std::size_t{0U}; number < invites; ++number)
    {
        auto const sender = "@a:o" + std::to_string(number % origins) + ".example";
        REQUIRE(store_invite(store, invite_from(sender, room_number(number))));
    }
}

[[nodiscard]] auto capped_store() -> db::PersistentStore
{
    auto store = db::PersistentStore{};
    store.local_server_name = "home.example";
    store.max_remote_invites_per_user = 8U;
    store.max_remote_invite_bytes_per_user = 1024U;
    store.max_remote_invites_per_origin = 100U;
    store.max_remote_knocks_per_user = 2U;
    store.remote_invite_origin_share_divisor = 2U;
    return store;
}

} // namespace

SCENARIO("a local user's remote invites are bounded in count before the write",
         "[database][invite][security][gate-m-sync]")
{
    GIVEN("a user one invite short of the limit, from several servers")
    {
        auto store = capped_store();
        fill_from_origins(store, 7U, 4U);
        REQUIRE(store.invites.size() == 7U);

        WHEN("one more arrives from a server under its share")
        {
            auto const stored = store_invite(store, invite_from("@a:fresh.example", room_number(100U)));

            THEN("it is stored: the limit itself is allowed")
            {
                REQUIRE(stored);
                REQUIRE(store.invites.size() == 8U);
            }

            AND_WHEN("another arrives past the limit")
            {
                auto const over = invite_from("@a:later.example", room_number(101U));
                auto const refused_up_front = db::invite_is_over_store_caps(store, over);
                auto const written = store_invite(store, over);
                auto const upserted = db::upsert_invite(store, over);

                THEN("every writer refuses it and nothing is written")
                {
                    REQUIRE(refused_up_front);
                    REQUIRE_FALSE(written);
                    REQUIRE_FALSE(upserted);
                    REQUIRE(store.invites.size() == 8U);
                    REQUIRE(db::find_membership_row(store, room_number(101U), victim) == nullptr);
                    REQUIRE_FALSE(db::find_invite(store, room_number(101U), victim).has_value());
                }
            }

            AND_WHEN("the event writer is offered it with its event")
            {
                auto event = db::PersistentEvent{};
                event.event_id = "$over";
                event.room_id = room_number(102U);
                event.sender_user_id = "@a:later.example";
                event.json = "{}";
                event.stream_ordering = 7U;
                event.status = "outlier";
                auto state = std::optional<db::PersistentStateEvent>{
                    db::PersistentStateEvent{room_number(102U), "m.room.member", std::string{victim}, "$over"}
                };
                auto const stored_event = db::store_event_with_state(
                    store, std::move(event), std::move(state),
                    db::MembershipProjection{std::string{victim}, "invite", 7U,
                                             invite_from("@a:later.example", room_number(102U))});

                THEN("the whole write is refused, the event included")
                {
                    REQUIRE_FALSE(stored_event);
                    REQUIRE(store.events.find("$over") == store.events.end());
                    REQUIRE(store.invites.size() == 8U);
                }
            }

            AND_WHEN("one of the held invites is ended")
            {
                REQUIRE(db::delete_invite(store, room_number(0U), victim));
                auto const next = store_invite(store, invite_from("@a:later.example", room_number(103U)));

                THEN("the place is free again")
                {
                    REQUIRE(next);
                    REQUIRE(store.invites.size() == 8U);
                }
            }

            AND_WHEN("the sender re-sends an invite already held")
            {
                auto const again = store_invite(store, invite_from("@a:fresh.example", room_number(100U)));

                THEN("a replacement is never refused on count")
                {
                    REQUIRE(again);
                    REQUIRE(store.invites.size() == 8U);
                }
            }
        }
    }
}

SCENARIO("a remote server cannot starve a user's invites from their own server",
         "[database][invite][security][gate-m-sync]")
{
    GIVEN("a user whose remote invites are at the limit")
    {
        auto store = capped_store();
        fill_from_origins(store, 8U, 4U);
        REQUIRE(db::invite_is_over_store_caps(store, invite_from("@a:later.example", room_number(100U))));

        WHEN("a user of the invitee's own server invites them")
        {
            auto const stored = store_invite(store, invite_from("@friend:home.example", "!local:home.example"));

            THEN("it is stored and not charged to the remote limit")
            {
                REQUIRE(stored);
                REQUIRE(store.invites.size() == 9U);
                REQUIRE(db::find_invite(store, "!local:home.example", victim).has_value());
            }
        }

        WHEN("a local user invites a user of another server, as an offer accepted there records")
        {
            for (auto number = std::size_t{200U}; number < 220U; ++number)
            {
                REQUIRE(store_invite(
                    store, invite_from("@friend:home.example", room_number(number), 2U, "@far:remote.example")));
            }

            THEN("nothing is charged to anyone, this server's own name included")
            {
                REQUIRE(store.invites.size() == 28U);
            }
        }

        WHEN("another local user is invited by the same servers")
        {
            auto const stored =
                store_invite(store, invite_from("@a:o1.example", room_number(100U), 2U, "@other:home.example"));

            THEN("their allowance is their own")
            {
                REQUIRE(stored);
            }
        }
    }
}

SCENARIO("one origin may use only a share of a user's allowance and of the server's",
         "[database][invite][security][gate-m-sync]")
{
    GIVEN("a share of one half of eight invites, and four held from one origin")
    {
        auto store = capped_store();
        fill_from_origins(store, 4U, 1U);

        WHEN("that origin sends a fifth")
        {
            auto const stored = store_invite(store, invite_from("@a:o0.example", room_number(100U)));

            THEN("it is refused, the user still having room")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.invites.size() == 4U);
            }
        }

        WHEN("a different origin sends one")
        {
            auto const stored = store_invite(store, invite_from("@a:fresh.example", room_number(100U)));

            THEN("it is stored")
            {
                REQUIRE(stored);
            }
        }
    }

    GIVEN("a server-wide limit of three invites from one origin, spread over users")
    {
        auto store = capped_store();
        store.max_remote_invites_per_origin = 3U;
        for (auto number = std::size_t{0U}; number < 3U; ++number)
        {
            auto const user = "@u" + std::to_string(number) + ":home.example";
            REQUIRE(store_invite(store, invite_from("@a:o.example", room_number(number), 2U, user)));
        }

        WHEN("the origin invites one user more")
        {
            auto const stored =
                store_invite(store, invite_from("@a:o.example", room_number(9U), 2U, "@u9:home.example"));

            THEN("it is refused, whichever user it names")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.invites.size() == 3U);
            }
        }
    }
}

SCENARIO("a user's stored remote invites are bounded in bytes", "[database][invite][security][gate-m-sync]")
{
    GIVEN("a user holding 800 of 1024 bytes")
    {
        auto store = capped_store();
        store.remote_invite_origin_share_divisor = 1U;
        REQUIRE(store_invite(store, invite_from("@a:o.example", room_number(1U), 800U)));

        WHEN("an invite of exactly the remaining 224 bytes arrives")
        {
            auto const stored = store_invite(store, invite_from("@a:p.example", room_number(2U), 224U));

            THEN("it is stored")
            {
                REQUIRE(stored);
            }
        }

        WHEN("an invite one byte larger arrives")
        {
            auto const stored = store_invite(store, invite_from("@a:p.example", room_number(2U), 225U));

            THEN("it is refused")
            {
                REQUIRE_FALSE(stored);
            }
        }

        WHEN("the held invite is replaced by one that fits the budget")
        {
            auto const stored = store_invite(store, invite_from("@a:o.example", room_number(1U), 1024U));

            THEN("only the net bytes are judged")
            {
                REQUIRE(stored);
            }
        }

        WHEN("the held invite is replaced by one over the budget")
        {
            auto const stored = store_invite(store, invite_from("@a:o.example", room_number(1U), 1025U));

            THEN("it is refused and the held row stays")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(db::find_invite(store, room_number(1U), victim)->signed_event_json.size() == 800U);
            }
        }
    }
}

SCENARIO("a user's knock records are bounded", "[database][invite][knock][security][gate-m-sync]")
{
    GIVEN("a user holding as many knocks as allowed")
    {
        auto store = capped_store();
        auto const knock = [](std::string const& room) {
            auto record = invite_from(victim, room);
            record.resident_server = "remote.example";
            return record;
        };
        auto const store_knock = [&](std::string const& room) {
            return db::store_membership_projection(store, room, {std::string{victim}, "knock", 1U, knock(room)});
        };
        REQUIRE(store_knock(room_number(1U)));
        REQUIRE(store_knock(room_number(2U)));

        WHEN("the user knocks on one room more")
        {
            auto const refused_up_front = db::invite_is_over_store_caps(store, knock(room_number(3U)));
            auto const stored = store_knock(room_number(3U));

            THEN("it is refused")
            {
                REQUIRE(refused_up_front);
                REQUIRE_FALSE(stored);
                REQUIRE(store.invites.size() == 2U);
            }
        }

        WHEN("a remote server invites the same user")
        {
            auto const stored = store_invite(store, invite_from("@a:o.example", room_number(9U)));

            THEN("knocks and invites are charged separately")
            {
                REQUIRE(stored);
            }
        }
    }
}

SCENARIO("an invite is found without reading the table", "[database][invite][security][gate-m-sync]")
{
    GIVEN("two thousand invites held for other users, as a loaded table is")
    {
        auto store = db::PersistentStore{};
        store.local_server_name = "home.example";
        for (auto number = std::size_t{0U}; number < 2000U; ++number)
        {
            store.invites.push_back(
                invite_from("@a:o.example", room_number(number), 2U, "@u" + std::to_string(number) + ":home.example"));
        }
        db::rebuild_invite_indexes(store);
        store.max_remote_invites_per_origin = 0U;
        REQUIRE(store_invite(store, invite_from("@a:o.example", room_number(5000U))));

        WHEN("the invite is looked up")
        {
            auto const before = store.invite_rows_examined.value();
            auto const* found = db::find_invite_row(store, room_number(5000U), victim);
            auto const copy = db::find_invite(store, room_number(5000U), victim);

            THEN("it is found for the cost of a key lookup")
            {
                REQUIRE(found != nullptr);
                REQUIRE(copy.has_value());
                REQUIRE(store.invite_rows_examined.value() - before <= 2U);
            }
        }

        WHEN("the invite is deleted, moving the last row into the gap")
        {
            REQUIRE(db::delete_invite(store, room_number(3U), "@u3:home.example"));

            THEN("every other invite is still found")
            {
                REQUIRE(db::find_invite_row(store, room_number(3U), "@u3:home.example") == nullptr);
                REQUIRE(db::find_invite_row(store, room_number(5000U), victim) != nullptr);
                REQUIRE(db::find_invite_row(store, room_number(1999U), "@u1999:home.example") != nullptr);
            }
        }

        WHEN("a row is pushed straight into the vector")
        {
            store.invites.push_back(invite_from("@a:o.example", "!direct:o.example"));

            THEN("the stale index is not trusted")
            {
                REQUIRE(db::find_invite_row(store, "!direct:o.example", victim) != nullptr);
            }
        }
    }
}

SCENARIO("one sending server's remote invites are bounded in bytes across every local user",
         "[database][invite][security][c04]")
{
    GIVEN("a server holding 60 of 100 bytes across two users")
    {
        auto store = capped_store();
        store.max_remote_invite_bytes_per_origin = 100U;
        store.max_remote_invite_bytes_total = 0U;
        store.max_remote_invite_bytes_per_user = 0U;
        REQUIRE(store_invite(store, invite_from("@a:o.example", room_number(1U), 30U, "@u1:home.example")));
        REQUIRE(store_invite(store, invite_from("@a:o.example", room_number(2U), 30U, "@u2:home.example")));

        WHEN("it sends exactly the remaining 40 bytes to a third user")
        {
            auto const stored =
                store_invite(store, invite_from("@a:o.example", room_number(3U), 40U, "@u3:home.example"));

            THEN("it is stored: the limit itself is allowed")
            {
                REQUIRE(stored);
            }
        }

        WHEN("it sends one byte more than remains, to a user it has not invited before")
        {
            auto const stored =
                store_invite(store, invite_from("@a:o.example", room_number(3U), 41U, "@u3:home.example"));

            THEN("it is refused and nothing is written")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.invites.size() == 2U);
            }
        }

        WHEN("another server sends the same bytes")
        {
            auto const stored =
                store_invite(store, invite_from("@a:p.example", room_number(3U), 41U, "@u3:home.example"));

            THEN("it is stored: the bound is per sending server")
            {
                REQUIRE(stored);
            }
        }

        WHEN("it re-sends an invite it already holds, larger but within the limit")
        {
            auto const stored =
                store_invite(store, invite_from("@a:o.example", room_number(1U), 70U, "@u1:home.example"));

            THEN("the record it replaces is not counted twice")
            {
                REQUIRE(stored);
            }
        }

        WHEN("one of its invites is rejected by the user and it sends the freed bytes again")
        {
            REQUIRE(db::delete_invite(store, room_number(1U), "@u1:home.example"));
            auto const stored =
                store_invite(store, invite_from("@a:o.example", room_number(3U), 70U, "@u3:home.example"));

            THEN("the freed bytes are available again")
            {
                REQUIRE(stored);
            }
        }
    }
}

SCENARIO("all remote invites together are bounded in bytes whatever the number of users",
         "[database][invite][security][c04]")
{
    GIVEN("two servers together holding 100 of 150 bytes")
    {
        auto store = capped_store();
        store.max_remote_invite_bytes_per_origin = 0U;
        store.max_remote_invite_bytes_total = 150U;
        store.max_remote_invite_bytes_per_user = 0U;
        REQUIRE(store_invite(store, invite_from("@a:o.example", room_number(1U), 50U, "@u1:home.example")));
        REQUIRE(store_invite(store, invite_from("@a:p.example", room_number(2U), 50U, "@u2:home.example")));

        WHEN("a third server sends 50 bytes")
        {
            auto const stored =
                store_invite(store, invite_from("@a:q.example", room_number(3U), 50U, "@u3:home.example"));

            THEN("it is stored: the total limit itself is allowed")
            {
                REQUIRE(stored);
            }
        }

        WHEN("a third server sends 51 bytes")
        {
            auto const stored =
                store_invite(store, invite_from("@a:q.example", room_number(3U), 51U, "@u3:home.example"));

            THEN("it is refused")
            {
                REQUIRE_FALSE(stored);
            }
        }

        WHEN("the rows are reloaded without the ledger, as after a restart, and a third server sends 51 bytes")
        {
            auto reloaded = db::PersistentStore{};
            reloaded.local_server_name = store.local_server_name;
            reloaded.max_remote_invite_bytes_per_origin = 0U;
            reloaded.max_remote_invite_bytes_total = 150U;
            reloaded.max_remote_invite_bytes_per_user = 0U;
            reloaded.invites = store.invites;
            auto const refused = db::invite_is_over_store_caps(
                reloaded, invite_from("@a:q.example", room_number(3U), 51U, "@u3:home.example"));
            auto const allowed = db::invite_is_over_store_caps(
                reloaded, invite_from("@a:q.example", room_number(3U), 50U, "@u3:home.example"));

            THEN("the check adds the rows up and gives the same answer")
            {
                REQUIRE(refused);
                REQUIRE_FALSE(allowed);
            }
        }
    }
}
