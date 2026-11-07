// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for homeserver::check_local_redaction, reconcile_redactions_for_event, reconcile_all_redactions
// and install_redaction_reconciler (CSAZ-11).
//
// Spec (rooms/v11.md, "Handling redactions"): a redaction is applied once both it and its target have been
// received, if the sender's power level is at least the redact level or the sender's domain matches the
// original event sender's domain. Spec (Client-Server API, PUT /redact): redacting others' events needs the
// `redact` power level; server administrators may redact events of users on their server.

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/LocalRedactionCheck.hpp"
#include "merovingian/homeserver/redaction_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStore;
using merovingian::homeserver::LocalRedactionCheck;

constexpr auto room = std::string_view{"!room:local.example"};
constexpr auto local = std::string_view{"local.example"};

auto add_event(PersistentStore& store, std::string_view event_id, std::string_view room_id, std::string json,
               std::uint64_t ordering) -> void
{
    auto event = PersistentEvent{};
    event.event_id = std::string{event_id};
    event.room_id = std::string{room_id};
    event.json = std::move(json);
    event.stream_ordering = ordering;
    event.depth = ordering;
    store.events.push_back(std::move(event));
}

[[nodiscard]] auto room_store() -> PersistentStore
{
    auto store = PersistentStore{};
    add_event(
        store, "$create", room,
        R"({"type":"m.room.create","sender":"@alice:local.example","state_key":"","content":{"room_version":"11"}})",
        1U);
    store.state.push_back({std::string{room}, "m.room.create", "", "$create"});
    add_event(
        store, "$pl", room,
        R"({"type":"m.room.power_levels","sender":"@alice:local.example","state_key":"","content":{"redact":50,"users":{"@alice:local.example":100}}})",
        2U);
    add_event(store, "$by_bob", room,
              R"({"type":"m.room.message","sender":"@bob:local.example","content":{"body":"b"}})", 3U);
    add_event(store, "$by_remote", room,
              R"({"type":"m.room.message","sender":"@carol:remote.example","content":{"body":"c"}})", 4U);
    add_event(store, "$elsewhere", "!other:local.example",
              R"({"type":"m.room.message","sender":"@bob:local.example","content":{"body":"e"}})", 5U);
    return store;
}

[[nodiscard]] auto redaction(std::string_view sender, std::string_view target) -> std::string
{
    // Room version 11 and later: `redacts` is in `content` (rooms/v11.md).
    return R"({"type":"m.room.redaction","sender":")" + std::string{sender} + R"(","room_id":")" + std::string{room} +
           R"(","content":{"redacts":")" + std::string{target} + R"("},"auth_events":["$pl"]})";
}

} // namespace

SCENARIO("A local redaction is permitted only when the sender may redact the target", "[homeserver][redaction][unit]")
{
    GIVEN("a v11 room where alice holds power level 100, redact needs 50, and bob and carol have none")
    {
        auto const store = room_store();

        WHEN("a user redacts their own event")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@bob:local.example", "$by_bob"), false, local);

            THEN("it is permitted")
            {
                REQUIRE(check == LocalRedactionCheck::permitted);
            }
        }

        WHEN("a user without the redact level redacts another user's event")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@bob:local.example", "$by_remote"), false, local);

            THEN("it is forbidden")
            {
                REQUIRE(check == LocalRedactionCheck::forbidden);
            }
        }

        WHEN("a user with the redact level redacts another user's event")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@alice:local.example", "$by_bob"), false, local);

            THEN("it is permitted")
            {
                REQUIRE(check == LocalRedactionCheck::permitted);
            }
        }

        WHEN("a server administrator without the redact level redacts a local user's event")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@dave:local.example", "$by_bob"), true, local);

            THEN("it is permitted")
            {
                REQUIRE(check == LocalRedactionCheck::permitted);
            }
        }

        WHEN("a server administrator without the redact level redacts a remote user's event")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@dave:local.example", "$by_remote"), true, local);

            THEN("administrator rights do not reach other servers' users")
            {
                REQUIRE(check == LocalRedactionCheck::forbidden);
            }
        }

        WHEN("the target is held in another room")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@alice:local.example", "$elsewhere"), false, local);

            THEN("the target is reported unknown")
            {
                REQUIRE(check == LocalRedactionCheck::target_unknown);
            }
        }

        WHEN("the target is not held and the sender holds the redact level")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@alice:local.example", "$not_yet_received"), false, local);

            THEN("it is permitted, to be judged when the target arrives")
            {
                REQUIRE(check == LocalRedactionCheck::permitted);
            }
        }

        WHEN("the target is not held and the sender lacks the redact level")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@bob:local.example", "$not_yet_received"), false, local);

            THEN("it is forbidden")
            {
                REQUIRE(check == LocalRedactionCheck::forbidden);
            }
        }

        WHEN("the redaction names no target, or is not JSON")
        {
            auto const no_target = merovingian::homeserver::check_local_redaction(
                store, room,
                R"({"type":"m.room.redaction","sender":"@alice:local.example","content":{},"auth_events":["$pl"]})",
                false, local);
            auto const garbage = merovingian::homeserver::check_local_redaction(store, room, "nope", false, local);

            THEN("both are forbidden")
            {
                REQUIRE(no_target == LocalRedactionCheck::forbidden);
                REQUIRE(garbage == LocalRedactionCheck::forbidden);
            }
        }
    }

    GIVEN("a room this server holds no create event for")
    {
        auto const store = PersistentStore{};

        WHEN("a redaction is checked")
        {
            auto const check = merovingian::homeserver::check_local_redaction(
                store, room, redaction("@alice:local.example", "$x"), true, local);

            THEN("it cannot be judged and is forbidden")
            {
                REQUIRE(check == LocalRedactionCheck::forbidden);
            }
        }
    }
}

SCENARIO("A stored redaction is applied once both it and its target are held", "[homeserver][redaction][unit]")
{
    GIVEN("a room with bob's message and, stored after it, bob's redaction of it")
    {
        auto store = room_store();
        add_event(store, "$redaction", room, redaction("@bob:local.example", "$by_bob"), 10U);
        merovingian::database::rebuild_redaction_state(store);

        WHEN("it is still withheld and the redaction is reconciled")
        {
            auto const withheld_before = merovingian::database::redaction_is_withheld(store, "$redaction");
            merovingian::homeserver::reconcile_redactions_for_event(store, "$redaction");

            THEN("the target's content is gone and the redaction is no longer withheld")
            {
                REQUIRE(withheld_before);
                REQUIRE_FALSE(merovingian::database::redaction_is_withheld(store, "$redaction"));
                REQUIRE(merovingian::database::applied_redaction_of(store, "$by_bob") ==
                        std::optional<std::string>{"$redaction"});
                REQUIRE(store.events.find("$by_bob")->json.find("\"body\"") == std::string::npos);
            }
            AND_WHEN("it is reconciled again")
            {
                auto const stored = store.events.find("$by_bob")->json;
                merovingian::homeserver::reconcile_redactions_for_event(store, "$redaction");

                THEN("nothing changes")
                {
                    REQUIRE(store.events.find("$by_bob")->json == stored);
                }
            }
        }

        WHEN("everything is reconciled at startup")
        {
            auto const applied = merovingian::homeserver::reconcile_all_redactions(store);

            THEN("one redaction is reported applied")
            {
                REQUIRE(applied == 1U);
            }
        }
    }

    GIVEN("a redaction whose sender may not redact the target")
    {
        auto store = room_store();
        add_event(store, "$redaction", room, redaction("@bob:local.example", "$by_remote"), 10U);
        merovingian::database::rebuild_redaction_state(store);

        WHEN("it is reconciled")
        {
            merovingian::homeserver::reconcile_redactions_for_event(store, "$redaction");

            THEN("the target is untouched and the redaction stays withheld")
            {
                REQUIRE(merovingian::database::redaction_is_withheld(store, "$redaction"));
                REQUIRE(store.events.find("$by_remote")->json.find("\"body\"") != std::string::npos);
            }
        }
    }

    GIVEN("a redaction whose target has not been received")
    {
        auto store = room_store();
        add_event(store, "$redaction", room, redaction("@bob:local.example", "$late"), 10U);
        merovingian::database::rebuild_redaction_state(store);
        merovingian::homeserver::reconcile_redactions_for_event(store, "$redaction");

        WHEN("the target arrives and is reconciled")
        {
            auto const withheld_before = merovingian::database::redaction_is_withheld(store, "$redaction");
            add_event(store, "$late", room,
                      R"({"type":"m.room.message","sender":"@bob:local.example","content":{"body":"l"}})", 11U);
            merovingian::homeserver::reconcile_redactions_for_event(store, "$late");

            THEN("the redaction waited, and is then applied")
            {
                REQUIRE(withheld_before);
                REQUIRE_FALSE(merovingian::database::redaction_is_withheld(store, "$redaction"));
                REQUIRE(store.events.find("$late")->json.find("\"body\"") == std::string::npos);
            }
        }
    }
}
