// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// CSAZ-10: /keys/query merged signatures by scanning every uploaded signature
// for every key it returned. Signatures are now indexed by target user so a
// lookup touches only that target's rows. The index must agree with the row
// vector after every mutation, reload and copy.

#include "../support/temp_directory.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

constexpr auto signature_json = R"({"signatures":{"@signer:example.org":{"ed25519:SSK":"sig"}}})";

[[nodiscard]] auto store_signature(merovingian::database::PersistentStore& store, std::string_view signer,
                                   std::string_view target_user, std::string_view target_key,
                                   std::string_view json = signature_json) -> bool
{
    return merovingian::database::store_key_signature(
        store, {std::string{signer}, std::string{target_user}, std::string{target_key}, std::string{json}});
}

[[nodiscard]] auto target_keys(merovingian::database::PersistentStore const& store, std::string_view target_user)
    -> std::vector<std::string>
{
    auto keys = std::vector<std::string>{};
    for (auto const& row : merovingian::database::key_signatures_for_target(store, target_user))
    {
        REQUIRE(row.get().target_user_id == target_user);
        keys.push_back(row.get().signer_user_id + ">" + row.get().target_device_id);
    }
    std::ranges::sort(keys);
    return keys;
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-key-sig-index-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("key signatures are looked up by target user", "[csaz-10][database][key-signatures][index]")
{
    GIVEN("signatures uploaded for several different targets")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(store_signature(store, "@signer:example.org", "@alice:example.org", "DEV1"));
        REQUIRE(store_signature(store, "@signer:example.org", "@bob:example.org", "DEV1"));
        REQUIRE(store_signature(store, "@other:example.org", "@alice:example.org", "DEV2"));
        REQUIRE(store_signature(store, "@signer:example.org", "@carol:example.org", "DEV9"));

        WHEN("one target is looked up")
        {
            THEN("exactly that target's rows are returned")
            {
                REQUIRE(target_keys(store, "@alice:example.org") ==
                        std::vector<std::string>{"@other:example.org>DEV2", "@signer:example.org>DEV1"});
                REQUIRE(target_keys(store, "@bob:example.org") == std::vector<std::string>{"@signer:example.org>DEV1"});
            }

            THEN("an unknown target has no rows")
            {
                REQUIRE(target_keys(store, "@nobody:example.org").empty());
            }
        }

        WHEN("an existing signature is replaced by a later upload")
        {
            REQUIRE(store_signature(store, "@signer:example.org", "@alice:example.org", "DEV1",
                                    R"({"signatures":{"@signer:example.org":{"ed25519:SSK":"newer"}}})"));

            THEN("the target still lists one row for that pair and it carries the new payload")
            {
                auto const rows = merovingian::database::key_signatures_for_target(store, "@alice:example.org");
                REQUIRE(rows.size() == 2U);
                auto const updated = std::ranges::find_if(rows, [](auto const& row) {
                    return row.get().signer_user_id == "@signer:example.org";
                });
                REQUIRE(updated != rows.end());
                REQUIRE(updated->get().json.find("newer") != std::string::npos);
                REQUIRE(store.key_signatures.size() == 4U);
            }
        }

        WHEN("the store is copied and the copy gains a signature")
        {
            auto copy = store;
            REQUIRE(store_signature(copy, "@signer:example.org", "@bob:example.org", "DEV2"));

            THEN("the copy sees its own rows and the original is unaffected")
            {
                REQUIRE(target_keys(copy, "@bob:example.org").size() == 2U);
                REQUIRE(target_keys(store, "@bob:example.org").size() == 1U);
            }
        }

        WHEN("the store is assigned from a copy and then moved")
        {
            auto assigned = merovingian::database::PersistentStore{};
            assigned = store;
            auto moved = std::move(assigned);

            THEN("the destination still answers per-target lookups")
            {
                REQUIRE(target_keys(moved, "@alice:example.org").size() == 2U);
                REQUIRE(target_keys(moved, "@carol:example.org").size() == 1U);
            }
        }
    }

    GIVEN("rows placed directly into the row vector, bypassing the store functions")
    {
        auto store = merovingian::database::PersistentStore{};
        store.key_signatures.push_back({"@signer:example.org", "@alice:example.org", "DEV1", signature_json});
        store.key_signatures.push_back({"@signer:example.org", "@bob:example.org", "DEV1", signature_json});

        WHEN("a target is looked up")
        {
            THEN("the result is still correct")
            {
                REQUIRE(target_keys(store, "@alice:example.org") ==
                        std::vector<std::string>{"@signer:example.org>DEV1"});
            }
        }

        WHEN("a signature is then stored through the store function")
        {
            REQUIRE(store_signature(store, "@signer:example.org", "@alice:example.org", "DEV2"));

            THEN("every row for the target is found, including the directly placed one")
            {
                REQUIRE(target_keys(store, "@alice:example.org").size() == 2U);
                REQUIRE(target_keys(store, "@bob:example.org").size() == 1U);
            }
        }
    }
}

SCENARIO("the key signature index is rebuilt when a durable store is reloaded",
         "[csaz-10][database][key-signatures][index][sqlite]")
{
    GIVEN("a SQLite store holding signatures for two targets")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        {
            auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(opened.ok);
            REQUIRE(store_signature(opened.store, "@signer:example.org", "@alice:example.org", "DEV1"));
            REQUIRE(store_signature(opened.store, "@signer:example.org", "@alice:example.org", "DEV2"));
            REQUIRE(store_signature(opened.store, "@signer:example.org", "@bob:example.org", "DEV1"));
        }

        WHEN("the store is reopened")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("per-target lookups return the persisted rows")
            {
                REQUIRE(target_keys(reopened.store, "@alice:example.org").size() == 2U);
                REQUIRE(target_keys(reopened.store, "@bob:example.org").size() == 1U);
                REQUIRE(target_keys(reopened.store, "@carol:example.org").empty());
            }

            THEN("a signature stored after the reload is found alongside the loaded ones")
            {
                REQUIRE(store_signature(reopened.store, "@signer:example.org", "@bob:example.org", "DEV2"));
                REQUIRE(target_keys(reopened.store, "@bob:example.org").size() == 2U);
                REQUIRE(target_keys(reopened.store, "@alice:example.org").size() == 2U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}
