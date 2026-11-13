// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The room state revision (ADR-0624) moves after the in-memory write of a prepared state row, not only when the write
// is prepared: a reader that stamps a revision between the two must find the stamp stale once the row changes (run-3
// C46, ADR-0697).

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

auto const room = std::string{"!room:example.org"};

[[nodiscard]] auto topic_event(std::string const& event_id, std::uint64_t depth)
    -> merovingian::database::PersistentEvent
{
    return merovingian::database::PersistentEvent{event_id,
                                                  room,
                                                  "@alice:example.org",
                                                  R"({"type":"m.room.topic","state_key":""})",
                                                  depth,
                                                  depth + 1U,
                                                  std::vector<std::string>{"$create:example.org"}};
}

[[nodiscard]] auto topic_row(std::string const& event_id) -> merovingian::database::PersistentStateEvent
{
    return merovingian::database::PersistentStateEvent{room, "m.room.topic", "", event_id};
}

} // namespace

SCENARIO("A room's state revision moves when a prepared state row is applied", "[database][state_revision][c46]")
{
    GIVEN("a room whose topic row exists")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_room_with_membership(store, {room, "@alice:example.org"},
                                                                  {room, "@alice:example.org"}));
        REQUIRE(merovingian::database::store_event_with_state(
            store,
            merovingian::database::PersistentEvent{"$create:example.org", room, "@alice:example.org",
                                                   R"({"type":"m.room.create","state_key":""})", 0U, 1U},
            merovingian::database::PersistentStateEvent{room, "m.room.create", "", "$create:example.org"}));
        REQUIRE(merovingian::database::store_event_with_state(store, topic_event("$topic1:example.org", 1U),
                                                              topic_row("$topic1:example.org")));

        WHEN("a new topic is prepared, the revision is read as a reader in the commit window would, and it is applied")
        {
            auto prepared = merovingian::database::prepare_store_event_with_state(
                store, topic_event("$topic2:example.org", 2U), topic_row("$topic2:example.org"));
            REQUIRE(prepared.has_value());
            REQUIRE(prepared->state_already_existed);
            auto const stamped = merovingian::database::room_state_revision(store, room);
            auto const row_when_stamped =
                merovingian::database::find_current_state_event_id(store, room, "m.room.topic", "");
            REQUIRE(merovingian::database::commit_persistent_transaction(store, prepared->statements));
            merovingian::database::apply_store_event_with_state(store, *prepared);

            THEN("the reader saw the old row, and the revision it stamped no longer matches")
            {
                REQUIRE(row_when_stamped == std::optional<std::string>{"$topic1:example.org"});
                REQUIRE(merovingian::database::find_current_state_event_id(store, room, "m.room.topic", "") ==
                        std::optional<std::string>{"$topic2:example.org"});
                REQUIRE(merovingian::database::room_state_revision(store, room) == stamped + 1U);
            }
        }

        WHEN("an event with no state is prepared and applied")
        {
            auto const before = merovingian::database::room_state_revision(store, room);
            auto message = topic_event("$message:example.org", 2U);
            message.json = R"({"type":"m.room.message"})";
            auto prepared = merovingian::database::prepare_store_event_with_state(store, std::move(message), {});
            REQUIRE(prepared.has_value());
            REQUIRE(merovingian::database::commit_persistent_transaction(store, prepared->statements));
            merovingian::database::apply_store_event_with_state(store, *prepared);

            THEN("the revision does not move")
            {
                REQUIRE(merovingian::database::room_state_revision(store, room) == before);
            }
        }
    }
}
