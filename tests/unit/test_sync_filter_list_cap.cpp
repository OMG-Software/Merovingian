// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Run-3 finding C09 (ADR-0657): every list of a sync filter (types, not_types, senders, not_senders, rooms, not_rooms,
// event_fields) holds at most 100 entries. The upload check refuses more, and the same cap is found again for inline
// filters and filters stored before it existed.
//
// Spec: Matrix Client-Server API v1.19, "Filtering": the filter schema; a server may refuse a definition it cannot
// serve. URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#filtering

#include "merovingian/sync/SyncFilter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>

namespace
{

namespace sync = merovingian::sync;

// A JSON list of `count` strings built by `make(index)`.
template <typename Make>
[[nodiscard]] auto list_of(std::size_t count, Make make) -> std::string
{
    auto out = std::string{"["};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        out += (index == 0U ? "" : ",") + std::string{"\""} + make(index) + "\"";
    }
    return out + "]";
}

[[nodiscard]] auto types(std::size_t count) -> std::string
{
    return list_of(count, [](std::size_t index) {
        return "m.type." + std::to_string(index) + ".*";
    });
}

[[nodiscard]] auto users(std::size_t count) -> std::string
{
    return list_of(count, [](std::size_t index) {
        return "@u" + std::to_string(index) + ":example.org";
    });
}

[[nodiscard]] auto rooms(std::size_t count) -> std::string
{
    return list_of(count, [](std::size_t index) {
        return "!r" + std::to_string(index) + ":example.org";
    });
}

} // namespace

SCENARIO("a filter list over the cap is refused at upload", "[sync][filter][c09][security]")
{
    GIVEN("filters whose lists hold exactly the cap")
    {
        WHEN("the filters are checked")
        {
            THEN("every list is accepted")
            {
                REQUIRE(sync::max_filter_list_entries == 100U);
                auto const at_cap = R"({"room":{"timeline":{"types":)" + types(100U) + R"(,"not_types":)" +
                                    types(100U) + R"(,"senders":)" + users(100U) + R"(,"not_senders":)" + users(100U) +
                                    R"(},"rooms":)" + rooms(100U) + R"(,"not_rooms":)" + rooms(100U) +
                                    R"(},"presence":{"types":)" + types(100U) + R"(},"account_data":{"not_types":)" +
                                    types(100U) + R"(},"event_fields":)" + types(100U) + "}";
                REQUIRE_FALSE(sync::validate_filter_definition(at_cap).has_value());
                REQUIRE_FALSE(sync::filter_list_cap_problem(at_cap).has_value());
            }
        }
    }

    GIVEN("a filter with one list one entry over the cap")
    {
        auto const check = [](std::string const& filter) {
            auto const upload = sync::validate_filter_definition(filter);
            auto const reread = sync::filter_list_cap_problem(filter);
            return upload.has_value() && reread.has_value() && upload->find("at most 100 entries") != std::string::npos;
        };

        WHEN("the filters are checked")
        {
            THEN("each list of each sub-filter is refused")
            {
                REQUIRE(check(R"({"room":{"timeline":{"types":)" + types(101U) + "}}}"));
                REQUIRE(check(R"({"room":{"timeline":{"not_types":)" + types(101U) + "}}}"));
                REQUIRE(check(R"({"room":{"state":{"senders":)" + users(101U) + "}}}"));
                REQUIRE(check(R"({"room":{"ephemeral":{"not_senders":)" + users(101U) + "}}}"));
                REQUIRE(check(R"({"room":{"account_data":{"types":)" + types(101U) + "}}}"));
                REQUIRE(check(R"({"room":{"rooms":)" + rooms(101U) + "}}"));
                REQUIRE(check(R"({"room":{"not_rooms":)" + rooms(101U) + "}}"));
                REQUIRE(check(R"({"presence":{"types":)" + types(101U) + "}}"));
                REQUIRE(check(R"({"account_data":{"not_types":)" + types(101U) + "}}"));
                REQUIRE(check(R"({"event_fields":)" + types(101U) + "}"));
            }
        }
    }

    GIVEN("a flat RoomEventFilter, as /messages and /context take")
    {
        WHEN("the filters are checked")
        {
            THEN("its lists are capped too, and the lenient parser itself stays lenient")
            {
                auto const over = R"({"types":)" + types(101U) + "}";
                REQUIRE(sync::filter_list_cap_problem(over).has_value());
                REQUIRE(sync::parse_room_event_filter_argument(over).has_value());
                auto const within = R"({"types":)" + types(100U) + "}";
                REQUIRE_FALSE(sync::filter_list_cap_problem(within).has_value());
                REQUIRE(sync::parse_room_event_filter_argument(within).has_value());
            }
        }
    }

    GIVEN("text that is not a JSON object")
    {
        WHEN("the filters are checked")
        {
            THEN("the cap check has nothing to say, so the other checks answer")
            {
                REQUIRE_FALSE(sync::filter_list_cap_problem("not json").has_value());
                REQUIRE_FALSE(sync::filter_list_cap_problem("[1,2]").has_value());
            }
        }
    }
}

SCENARIO("a filter at the cap still filters correctly", "[sync][filter][c09]")
{
    GIVEN("a types list of 100 patterns whose last one is the wanted type")
    {
        auto list = std::string{"["};
        for (auto index = std::size_t{0U}; index < 99U; ++index)
        {
            list += "\"m.nothing." + std::to_string(index) + "\",";
        }
        list += "\"m.room.*\"]";
        auto const filter = sync::parse_filter_argument(R"({"room":{"timeline":{"types":)" + list + "}}}");

        WHEN("the filters are checked")
        {
            THEN("a matching type passes and another does not")
            {
                REQUIRE(filter.room.timeline.types.size() == 100U);
                REQUIRE(sync::event_passes_filter(filter.room.timeline, "m.room.message", "@a:example.org"));
                REQUIRE_FALSE(sync::event_passes_filter(filter.room.timeline, "m.other", "@a:example.org"));
            }
        }
    }
}
