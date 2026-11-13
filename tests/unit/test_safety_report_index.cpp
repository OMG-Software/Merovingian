// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C26 (ADR-0686): the index the reporting routes use instead of reading audit_log per report. Spec: Matrix
// Client-Server API v1.19, "POST /rooms/{roomId}/report/{eventId}" and "POST /users/{userId}/report" (a server may
// refuse a flood with 429 M_LIMIT_EXCEEDED).

#include "merovingian/database/PersistentAuditEvent.hpp"
#include "merovingian/homeserver/SafetyReportIndex.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace
{

using merovingian::homeserver::SafetyReportIndex;
using Admission = SafetyReportIndex::Admission;

constexpr auto event_type = "trust_safety.account.accept_report";
constexpr auto capacity = std::size_t{1000U};

} // namespace

SCENARIO("A repeated report is acknowledged and a new one admitted", "[trust-safety][c26][reports]")
{
    GIVEN("an index that has admitted one report")
    {
        auto index = SafetyReportIndex{};
        REQUIRE(index.admit(event_type, "@a:example.org", "@b:example.org", 1000U, capacity) == Admission::admitted);

        WHEN("the same reporter reports the same target again, and another reporter reports it")
        {
            auto const repeat = index.admit(event_type, "@a:example.org", "@b:example.org", 2000U, capacity);
            auto const other = index.admit(event_type, "@c:example.org", "@b:example.org", 2000U, capacity);

            THEN("the repeat is a duplicate and the other reporter's report is admitted")
            {
                REQUIRE(repeat == Admission::duplicate);
                REQUIRE(other == Admission::admitted);
                REQUIRE(index.size() == 2U);
            }
        }
    }
}

SCENARIO("One reporter's distinct reports are bounded per day", "[trust-safety][c26][reports]")
{
    GIVEN("a reporter who has filed the daily share of distinct reports")
    {
        auto index = SafetyReportIndex{};
        auto const reporter = std::string{"@a:example.org"};
        for (auto number = std::size_t{0U}; number < merovingian::homeserver::max_safety_reports_per_reporter; ++number)
        {
            REQUIRE(index.admit(event_type, reporter, "@t" + std::to_string(number) + ":example.org", 1000U,
                                capacity) == Admission::admitted);
        }

        WHEN("they report one more target, a repeat, and another reporter reports")
        {
            auto const over = index.admit(event_type, reporter, "@extra:example.org", 2000U, capacity);
            auto const repeat = index.admit(event_type, reporter, "@t0:example.org", 2000U, capacity);
            auto const other = index.admit(event_type, "@c:example.org", "@extra:example.org", 2000U, capacity);

            THEN("the new one is refused, the repeat is still acknowledged and the other reporter is served")
            {
                REQUIRE(over == Admission::reporter_over_budget);
                REQUIRE(repeat == Admission::duplicate);
                REQUIRE(other == Admission::admitted);
                REQUIRE(index.reporter_reports(reporter) == merovingian::homeserver::max_safety_reports_per_reporter);
            }
        }

        WHEN("a day has passed")
        {
            auto const later = index.admit(event_type, reporter, "@extra:example.org",
                                           1000U + merovingian::homeserver::safety_report_budget_window_ms, capacity);

            THEN("the reporter may report again")
            {
                REQUIRE(later == Admission::admitted);
            }
        }
    }
}

SCENARIO("The index remembers only the window of reports the listing shows", "[trust-safety][c26][reports]")
{
    GIVEN("an index with a capacity of three reports")
    {
        auto index = SafetyReportIndex{};
        for (auto number = 0; number < 4; ++number)
        {
            REQUIRE(index.admit(event_type, "@a:example.org", "@t" + std::to_string(number) + ":example.org", 1000U,
                                3U) == Admission::admitted);
        }

        WHEN("the oldest report is reported again and the newest is reported again")
        {
            auto const oldest = index.admit(event_type, "@a:example.org", "@t0:example.org", 2000U, 3U);
            auto const newest = index.admit(event_type, "@a:example.org", "@t3:example.org", 2000U, 3U);

            THEN("the oldest has left the window and is admitted anew, the newest is a duplicate")
            {
                REQUIRE(oldest == Admission::admitted);
                REQUIRE(newest == Admission::duplicate);
                REQUIRE(index.size() == 3U);
            }
        }
    }
}

SCENARIO("The index is rebuilt from the report rows the audit log holds", "[trust-safety][c26][reports]")
{
    GIVEN("rows newest first: two reports, a policy rule change, and a report by another reporter")
    {
        auto rows = std::vector<merovingian::database::PersistentAuditEvent>{
            {"policy", "trust_safety.room.accept_report", "@a:example.org",     "$e2",            "ok",    3000U},
            {"policy", "trust_safety.policy_rule.upsert", "@admin:example.org", "media:x",        "allow", 2900U},
            {"policy", event_type,                        "@a:example.org",     "@b:example.org", "ok",    2000U},
            {"policy", event_type,                        "@c:example.org",     "@b:example.org", "ok",    1000U},
        };
        auto index = SafetyReportIndex{};

        WHEN("it is rebuilt")
        {
            index.rebuild(rows, "accept_report", capacity);

            THEN("only report rows are remembered, with their reporters' counts")
            {
                REQUIRE(index.size() == 3U);
                REQUIRE(index.reporter_reports("@a:example.org") == 2U);
                REQUIRE(index.reporter_reports("@admin:example.org") == 0U);
                REQUIRE(index.admit(event_type, "@a:example.org", "@b:example.org", 4000U, capacity) ==
                        Admission::duplicate);
                REQUIRE(index.admit(event_type, "@d:example.org", "@b:example.org", 4000U, capacity) ==
                        Admission::admitted);
            }
        }
    }
}
