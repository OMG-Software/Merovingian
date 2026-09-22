// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0064 phase B1: source-tree guard test. Every locally created or
// inbound-accepted event must go through code that maintains its
// state-group / forward-extremity bookkeeping — database::store_event_with_state
// itself does not. persist_composed_event/send_event (room_service.cpp) and
// ingest_pdu_event (local_http_router.cpp) both learned this the hard way:
// each silently bypassed bookkeeping for months before the regression was
// caught by tests/unit/test_local_event_state_bookkeeping.cpp. This test
// fails the build the moment a NEW call site appears anywhere in src/ that
// is not one of the reviewed, documented exceptions below, so that
// regression cannot recur unnoticed.
//
// Style follows tests/unit/test_worker_db_uri.cpp's source-tree consistency
// scenarios: reads the checked-in .cpp files directly (not runtime data) via
// MEROVINGIAN_TEST_SOURCE_ROOT.

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

namespace
{

[[nodiscard]] auto source_root() -> std::filesystem::path
{
#ifdef MEROVINGIAN_TEST_SOURCE_ROOT
    return std::filesystem::path{MEROVINGIAN_TEST_SOURCE_ROOT};
#else
    return std::filesystem::current_path();
#endif
}

[[nodiscard]] auto read_whole_file(std::filesystem::path const& path) -> std::string
{
    auto input = std::ifstream{path, std::ios::binary};
    REQUIRE(input.is_open());
    auto buffer = std::ostringstream{};
    buffer << input.rdbuf();
    return buffer.str();
}

[[nodiscard]] auto count_occurrences(std::string const& text, std::string const& needle) -> std::size_t
{
    auto count = std::size_t{0U};
    auto pos = std::size_t{0U};
    while ((pos = text.find(needle, pos)) != std::string::npos)
    {
        ++count;
        pos += needle.size();
    }
    return count;
}

// Every path here relative to the source root, and every count here, is a
// call site reviewed against ADR-0064: it either has its own bookkeeping
// (the choke point itself, membership_acceptor, the join event's snapshot-
// based seeding) or is a deliberate "outlier" event that must NOT get a
// state group or forward extremity (ingest_send_join_state's state/
// auth-chain events, invite_handler's auth-chain-lookup-only invite).
// Update this map, with a comment explaining the new exception, when a
// genuinely new one is added — do not simply raise a count to make this
// test pass.
[[nodiscard]] auto reviewed_call_sites() -> std::map<std::string, std::size_t>
{
    return {
        // The choke point itself (homeserver::store_local_event).
        {"src/homeserver/state_bookkeeping.cpp", 1U},
        // ingest_send_join_state's critical-state loop (outlier),
        // join_room's auth-chain persist loop (outlier), and the join
        // event's own store (bespoke snapshot-parent bookkeeping via
        // record_event_state_with_parent — see join_room).
        {"src/homeserver/room_service.cpp",      3U},
        // membership_acceptor (inbound send_join/send_leave/send_knock
        // acceptance — has its own compute_state_before/record_event_state/
        // recompute_current_state sequence, the same trust boundary as
        // ingest_pdu_event) and invite_handler (outlier).
        {"src/homeserver/local_http_router.cpp", 2U},
    };
}

} // namespace

SCENARIO("Every database::store_event_with_state call site in src/ is a reviewed ADR-0064 exception",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("the checked-in src/ tree, excluding src/database/ (the store abstraction itself)")
    {
        auto const src_dir = source_root() / "src";
        REQUIRE(std::filesystem::exists(src_dir));

        auto actual = std::map<std::string, std::size_t>{};
        for (auto const& entry : std::filesystem::recursive_directory_iterator{src_dir})
        {
            if (!entry.is_regular_file() || entry.path().extension() != ".cpp")
            {
                continue;
            }
            auto const relative = std::filesystem::relative(entry.path(), source_root());
            auto relative_str = relative.generic_string();
            if (relative_str.starts_with("src/database/"))
            {
                continue; // the store abstraction itself
            }
            auto const contents = read_whole_file(entry.path());
            auto const count = count_occurrences(contents, "database::store_event_with_state(");
            if (count > 0U)
            {
                actual[relative_str] = count;
            }
        }

        WHEN("every call site found is compared against the reviewed allowlist")
        {
            auto const expected = reviewed_call_sites();

            THEN("no file outside the allowlist calls it, and every allowlisted count matches exactly")
            {
                for (auto const& [file, count] : actual)
                {
                    INFO("unexpected or changed database::store_event_with_state call site: " << file << " (" << count
                                                                                              << " occurrence(s))");
                    auto const expected_it = expected.find(file);
                    REQUIRE(expected_it != expected.end());
                    REQUIRE(count == expected_it->second);
                }
                for (auto const& [file, count] : expected)
                {
                    INFO("reviewed call site no longer found (route it through the choke point and remove the "
                         "allowlist entry, do not leave it stale): "
                         << file);
                    auto const actual_it = actual.find(file);
                    REQUIRE(actual_it != actual.end());
                    REQUIRE(actual_it->second == count);
                }
            }
        }
    }
}
