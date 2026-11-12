// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/sync/SlidingSyncLimits.hpp"
#include "merovingian/sync/SlidingSyncParser.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using merovingian::sync::parse_sliding_sync_request;
using merovingian::sync::sliding_sync_request_limit_violation;
using merovingian::sync::sliding_sync_retained_bytes;
using merovingian::sync::SlidingSyncLimits;

// A body whose one list filters on `count` strings named by `key`.
[[nodiscard]] auto body_with_strings(std::string_view key, std::size_t count, std::string_view text) -> std::string
{
    auto body = std::string{R"({"lists":{"a":{"ranges":[[0,0]],"filters":{")"} + std::string{key} + R"(":[)";
    for (auto i = std::size_t{0U}; i < count; ++i)
    {
        body += i == 0U ? "" : ",";
        body += '"' + std::string{text} + '"';
    }
    body += "]}}}}";
    return body;
}

[[nodiscard]] auto violation_of(std::string const& body) -> std::optional<std::string_view>
{
    auto const parsed = parse_sliding_sync_request(body);
    REQUIRE(parsed.has_value());
    return sliding_sync_request_limit_violation(*parsed);
}

[[nodiscard]] auto required_state_body(std::size_t type_size) -> std::string
{
    return R"({"lists":{"a":{"ranges":[[0,0]],"required_state":[[")" + std::string(type_size, 't') + R"(",""]]}}})";
}

} // namespace

SCENARIO("A sliding sync request cannot make a connection keep an unbounded filter list",
         "[sync][sliding-sync][retained-size][unit]")
{
    GIVEN("the default limits of 16 room types")
    {
        REQUIRE(SlidingSyncLimits{}.room_types == 16U);

        WHEN("a list names exactly 16 room_types")
        {
            THEN("the request is admitted")
            {
                REQUIRE_FALSE(violation_of(body_with_strings("room_types", 16U, "m.space")).has_value());
            }
        }
        WHEN("a list names 17 room_types")
        {
            auto const violation = violation_of(body_with_strings("room_types", 17U, "m.space"));
            THEN("the request is refused")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many room_types in a list");
            }
        }
        WHEN("a list names 16 and 17 not_room_types")
        {
            auto const at_cap = violation_of(body_with_strings("not_room_types", 16U, "m.space"));
            auto const over_cap = violation_of(body_with_strings("not_room_types", 17U, "m.space"));
            THEN("16 is admitted and 17 refused")
            {
                REQUIRE_FALSE(at_cap.has_value());
                REQUIRE(over_cap.has_value());
                REQUIRE(*over_cap == "too many not_room_types in a list");
            }
        }
        WHEN("a body of about 1 MiB of empty room_types strings is sent")
        {
            auto const body = body_with_strings("room_types", 349'000U, "");
            REQUIRE(body.size() > 1'000'000U);
            auto const violation = violation_of(body);
            THEN("it is refused, so nothing of it is retained")
            {
                REQUIRE(violation.has_value());
                REQUIRE(*violation == "too many room_types in a list");
            }
        }
    }
}

SCENARIO("A sliding sync request cannot make a connection keep many ranges or a long name",
         "[sync][sliding-sync][retained-size][unit]")
{
    GIVEN("ranges, a conn_id and a list name at and over their caps")
    {
        auto const ranges_body = [](std::size_t count) {
            auto body = std::string{R"({"lists":{"a":{"ranges":[)"};
            for (auto i = std::size_t{0U}; i < count; ++i)
            {
                auto const at = std::to_string(i * 2U);
                body += (i == 0U ? "[" : ",[") + at + "," + at + "]";
            }
            return body + "]}}}";
        };

        WHEN("a list has 16 ranges, then 17")
        {
            auto const at_cap = violation_of(ranges_body(16U));
            auto const over_cap = violation_of(ranges_body(17U));
            THEN("16 is admitted and 17 refused")
            {
                REQUIRE_FALSE(at_cap.has_value());
                REQUIRE(over_cap.has_value());
                REQUIRE(*over_cap == "too many ranges in a list");
            }
        }
        WHEN("a conn_id is 255 bytes, then 256")
        {
            auto const at_cap = violation_of(R"({"conn_id":")" + std::string(255U, 'c') + R"("})");
            auto const over_cap = violation_of(R"({"conn_id":")" + std::string(256U, 'c') + R"("})");
            THEN("255 is admitted and 256 refused")
            {
                REQUIRE_FALSE(at_cap.has_value());
                REQUIRE(over_cap.has_value());
                REQUIRE(*over_cap == "conn_id too long");
            }
        }
        WHEN("a list name is 255 bytes, then 256")
        {
            auto const named = [](std::size_t size) {
                return R"({"lists":{")" + std::string(size, 'n') + R"(":{"ranges":[[0,0]]}}})";
            };
            auto const at_cap = violation_of(named(255U));
            auto const over_cap = violation_of(named(256U));
            THEN("255 is admitted and 256 refused")
            {
                REQUIRE_FALSE(at_cap.has_value());
                REQUIRE(over_cap.has_value());
                REQUIRE(*over_cap == "list name too long");
            }
        }
    }
}

SCENARIO("The bytes a sliding sync connection keeps of its lists are bounded",
         "[sync][sliding-sync][retained-size][unit]")
{
    GIVEN("a request shaped like the one Element X sends, with two lists")
    {
        auto const body =
            std::string{R"({"conn_id":"room-list","lists":{"all_rooms":{"ranges":[[0,19]],"timeline_limit":1,)"
                        R"("required_state":[["m.room.name",""],["m.room.avatar",""],["m.room.canonical_alias",""]]},)"
                        R"("invites":{"ranges":[[0,19]],"filters":{"is_invite":true,"not_room_types":["m.space"]}}}})"};
        auto const parsed = parse_sliding_sync_request(body);
        REQUIRE(parsed.has_value());

        THEN("it is admitted and weighs far less than the per-connection budget")
        {
            REQUIRE_FALSE(sliding_sync_request_limit_violation(*parsed).has_value());
            REQUIRE(sliding_sync_retained_bytes(*parsed) < SlidingSyncLimits{}.retained_bytes_per_connection / 8U);
            REQUIRE(sliding_sync_retained_bytes(*parsed) > sliding_sync_retained_bytes(parsed->lists));
        }
    }

    GIVEN("a required_state type string longer than the whole per-connection budget")
    {
        auto const violation = violation_of(required_state_body(70'000U));

        THEN("the request is refused for its size")
        {
            REQUIRE(violation.has_value());
            REQUIRE(*violation == "the lists are too large to keep for a connection");
        }
    }

    GIVEN("required_state strings sized to the budget exactly and one byte over")
    {
        auto const parsed = parse_sliding_sync_request(required_state_body(60'000U));
        REQUIRE(parsed.has_value());
        auto const base = sliding_sync_retained_bytes(*parsed);
        auto const budget = std::uint64_t{SlidingSyncLimits{}.retained_bytes_per_connection};
        REQUIRE(base <= budget);
        auto const slack = static_cast<std::size_t>(budget - base);

        THEN("exactly at the budget is admitted and one byte more is refused")
        {
            REQUIRE_FALSE(violation_of(required_state_body(60'000U + slack)).has_value());
            REQUIRE(violation_of(required_state_body(60'000U + slack + 1U)).has_value());
        }
    }
}
