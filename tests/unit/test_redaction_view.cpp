// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for database::add_redaction_compat and database::attach_redacted_because (CSAZ-11).
//
// Spec (rooms/v11.md, "Moving the `redacts` property"): servers add `redacts` at the top level of
// m.room.redaction events they serve, and to `content` for older room versions.
// Spec (client-server-api.md, "Redactions"): servers include the m.room.redaction event under
// `unsigned` as `redacted_because` when serving the redacted event.

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/RedactionView.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <variant>

namespace
{

[[nodiscard]] auto object_of(std::string const& json) -> merovingian::canonicaljson::Object
{
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

[[nodiscard]] auto text_of(merovingian::canonicaljson::Object object) -> std::string
{
    return merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(object)}).output;
}

} // namespace

SCENARIO("A redaction served to clients carries redacts in both places", "[database][redaction][unit]")
{
    GIVEN("a redaction event with redacts only at the top level")
    {
        auto event = object_of(R"({"type":"m.room.redaction","redacts":"$t","content":{"reason":"spam"}})");

        WHEN("the compatibility field is added")
        {
            merovingian::database::add_redaction_compat(event);

            THEN("content gains redacts and the top level is untouched")
            {
                REQUIRE(text_of(event) ==
                        R"({"content":{"reason":"spam","redacts":"$t"},"redacts":"$t","type":"m.room.redaction"})");
            }
        }
    }

    GIVEN("a redaction event with redacts only in content")
    {
        auto event = object_of(R"({"type":"m.room.redaction","content":{"redacts":"$t"}})");

        WHEN("the compatibility field is added")
        {
            merovingian::database::add_redaction_compat(event);

            THEN("the top level gains redacts")
            {
                REQUIRE(text_of(event) == R"({"content":{"redacts":"$t"},"redacts":"$t","type":"m.room.redaction"})");
            }
        }
    }

    GIVEN("events that need no change")
    {
        auto both = object_of(R"({"type":"m.room.redaction","redacts":"$a","content":{"redacts":"$b"}})");
        auto neither = object_of(R"({"type":"m.room.redaction","content":{}})");
        auto other = object_of(R"({"type":"m.room.message","redacts":"$t","content":{}})");

        WHEN("the compatibility field is added")
        {
            merovingian::database::add_redaction_compat(both);
            merovingian::database::add_redaction_compat(neither);
            merovingian::database::add_redaction_compat(other);

            THEN("a redaction with both, a redaction with neither and a non-redaction are left alone")
            {
                REQUIRE(text_of(both) == R"({"content":{"redacts":"$b"},"redacts":"$a","type":"m.room.redaction"})");
                REQUIRE(text_of(neither) == R"({"content":{},"type":"m.room.redaction"})");
                REQUIRE(text_of(other) == R"({"content":{},"redacts":"$t","type":"m.room.message"})");
            }
        }
    }
}

SCENARIO("A redacted event is served with the redaction under unsigned", "[database][redaction][unit]")
{
    GIVEN("a store holding a redaction event that has been applied to $target")
    {
        auto store = merovingian::database::PersistentStore{};
        auto redaction = merovingian::database::PersistentEvent{};
        redaction.event_id = "$redaction";
        redaction.room_id = "!r:x";
        redaction.json = R"({"type":"m.room.redaction","event_id":"$stale","redacts":"$target","content":{},)"
                         R"("unsigned":{"age":9}})";
        store.events.push_back(redaction);
        merovingian::database::mark_redaction_applied(store, "$redaction", "$target");

        WHEN("the redacted event is served")
        {
            auto client_event = object_of(R"({"type":"m.room.message","unsigned":{"age":1,"redacted_because":1}})");
            merovingian::database::attach_redacted_because(store, "$target", client_event);

            THEN("redacted_because is the redaction with its own event_id, compat redacts, and no nested unsigned")
            {
                REQUIRE(text_of(client_event) ==
                        R"({"type":"m.room.message","unsigned":{"age":1,"redacted_because":{)"
                        R"("content":{"redacts":"$target"},"event_id":"$redaction","redacts":"$target",)"
                        R"("type":"m.room.redaction"}}})");
            }
        }

        WHEN("an event with no unsigned member is served")
        {
            auto client_event = object_of(R"({"type":"m.room.message"})");
            merovingian::database::attach_redacted_because(store, "$target", client_event);

            THEN("an unsigned object is created")
            {
                REQUIRE(text_of(client_event).find(R"("unsigned":{"redacted_because":)") != std::string::npos);
            }
        }

        WHEN("an event that was not redacted is served")
        {
            auto client_event = object_of(R"({"type":"m.room.message"})");
            merovingian::database::attach_redacted_because(store, "$other", client_event);

            THEN("it is unchanged")
            {
                REQUIRE(text_of(client_event) == R"({"type":"m.room.message"})");
            }
        }
    }

    GIVEN("an applied redaction whose event is not stored, or is not JSON")
    {
        auto store = merovingian::database::PersistentStore{};
        merovingian::database::mark_redaction_applied(store, "$missing", "$t1");
        auto broken = merovingian::database::PersistentEvent{};
        broken.event_id = "$broken";
        broken.json = "not json";
        store.events.push_back(broken);
        merovingian::database::mark_redaction_applied(store, "$broken", "$t2");

        WHEN("the targets are served")
        {
            auto first = object_of(R"({"type":"m.room.message"})");
            auto second = object_of(R"({"type":"m.room.message"})");
            merovingian::database::attach_redacted_because(store, "$t1", first);
            merovingian::database::attach_redacted_because(store, "$t2", second);

            THEN("both are left unchanged rather than served with a partial redaction")
            {
                REQUIRE(text_of(first) == R"({"type":"m.room.message"})");
                REQUIRE(text_of(second) == R"({"type":"m.room.message"})");
            }
        }
    }
}
