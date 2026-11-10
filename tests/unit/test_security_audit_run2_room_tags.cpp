// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-2, F-12 (ADR-0339). PUT .../rooms/{roomId}/tags/{tag} read-modified-wrote one
// m.tag account-data row with no bound on tag count, tag name or row size, so the row outgrew any
// request body and every later tag request and /sync parsed it whole under runtime.mutex.
//
// Spec: client-server-api.md, "Room Tagging": "The name of a tag MUST NOT exceed 255 bytes." The
// spec states no count or row limit; those are ADR-0339 decisions, enforced for rows the server
// writes itself as well as for a client's account-data PUT.

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

SCENARIO("an account-data row over the row limit is refused whoever writes it",
         "[database][account-data][security][run2][f12]")
{
    GIVEN("a store holding a small global row for alice")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::store_account_data(store, {"@alice:example.org", "", "m.a", R"({})", 0U}));
        auto const oversized =
            std::string{R"({"pad":")"} + std::string(merovingian::database::max_account_data_row_bytes, 'x') + R"("})";

        WHEN("a row over the limit is stored by the server's own writer")
        {
            auto const stored = merovingian::database::store_account_data(
                store, {"@alice:example.org", "!r:example.org", "m.tag", oversized, 0U});

            THEN("it is refused and the mirror is unchanged")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(store.account_data.size() == 1U);
            }
        }

        WHEN("an update of the held type is over the limit through the capped writer")
        {
            auto const outcome = merovingian::database::store_global_account_data_within_cap(
                store, {"@alice:example.org", "", "m.a", oversized, 0U}, 10U);

            THEN("it is refused as too large and the old row stays")
            {
                REQUIRE(outcome == merovingian::database::CappedAccountDataStore::too_large);
                REQUIRE(store.account_data.front().content_json == R"({})");
            }
        }

        WHEN("a row exactly at the limit is stored")
        {
            auto const overhead = std::string_view{R"({"pad":""})"}.size();
            auto const at_limit = std::string{R"({"pad":")"} +
                                  std::string(merovingian::database::max_account_data_row_bytes - overhead, 'x') +
                                  R"("})";
            auto const stored =
                merovingian::database::store_account_data(store, {"@alice:example.org", "", "m.b", at_limit, 0U});

            THEN("it is kept")
            {
                REQUIRE(stored);
                REQUIRE(store.account_data.size() == 2U);
            }
        }
    }
}
