// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// CSAZ-10: spec v1.19 (client-server-api.md, POST /_matrix/client/v3/keys/upload,
// `fallback_keys`) allows "at most one key per algorithm" and the server "will only
// persist one key per algorithm". A device that kept every fallback key it ever
// uploaded grew without bound.

#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

SCENARIO("a device that uploads a new fallback key for an algorithm keeps only that key",
         "[csaz-10][e2ee][database][fallback-key]")
{
    GIVEN("a store holding a signed_curve25519 and a curve25519 fallback key for one device")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::store_fallback_key(
            store, {"@alice:example.org", "DEVICE1", "signed_curve25519:OLD", R"({"key":"old"})"}));
        REQUIRE(merovingian::database::store_fallback_key(
            store, {"@alice:example.org", "DEVICE1", "curve25519:OTHER", R"("other")"}));

        WHEN("a signed_curve25519 fallback key with a different key id is stored")
        {
            REQUIRE(merovingian::database::store_fallback_key(
                store, {"@alice:example.org", "DEVICE1", "signed_curve25519:NEW", R"({"key":"new"})"}));

            THEN("exactly one signed_curve25519 fallback key remains and it is the new one")
            {
                auto const signed_keys = std::ranges::count_if(store.fallback_keys, [](auto const& key) {
                    return key.key_id.starts_with("signed_curve25519:");
                });
                REQUIRE(signed_keys == 1);
                auto const found = merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1",
                                                                            "signed_curve25519");
                REQUIRE(found.has_value());
                REQUIRE(found->key_id == "signed_curve25519:NEW");
            }

            THEN("the fallback key of the other algorithm is untouched")
            {
                auto const other =
                    merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1", "curve25519");
                REQUIRE(other.has_value());
                REQUIRE(other->key_id == "curve25519:OTHER");
                REQUIRE(store.fallback_keys.size() == 2U);
            }
        }

        WHEN("another device stores a fallback key for the same algorithm")
        {
            REQUIRE(merovingian::database::store_fallback_key(
                store, {"@alice:example.org", "DEVICE2", "signed_curve25519:NEW", R"({"key":"new"})"}));

            THEN("the first device keeps its own key")
            {
                auto const first = merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1",
                                                                            "signed_curve25519");
                REQUIRE(first.has_value());
                REQUIRE(first->key_id == "signed_curve25519:OLD");
            }
        }

        WHEN("the durable write for the replacement fails")
        {
            store.force_next_persist_failures = 1U;
            auto const stored = merovingian::database::store_fallback_key(
                store, {"@alice:example.org", "DEVICE1", "signed_curve25519:NEW", R"({"key":"new"})"});

            THEN("the store reports failure and the previous key is still the only one held")
            {
                REQUIRE_FALSE(stored);
                auto const found = merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1",
                                                                            "signed_curve25519");
                REQUIRE(found.has_value());
                REQUIRE(found->key_id == "signed_curve25519:OLD");
            }
        }
    }
}
