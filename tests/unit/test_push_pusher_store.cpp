// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/persistent_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Persistent store upserts, finds, lists, and deletes pushers", "[database][persistence][push]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("alice registers an http pusher and the same (user_id, app_id, pushkey) is upserted with updated fields")
        {
            REQUIRE(merovingian::database::store_pusher(
                store, {"@alice:example.org", "org.example.app.ios", "abc123", "http", "Example App", "iPhone", "",
                        "en", "https://push.example.org/_matrix/push/v1/notify", ""}));
            REQUIRE(merovingian::database::store_pusher(
                store, {"@alice:example.org", "org.example.app.ios", "abc123", "http", "Example App v2", "iPhone 15",
                        "xyz", "en-US", "https://push.example.org/_matrix/push/v1/notify", "event_id_only"}));

            auto const stored =
                merovingian::database::find_pusher(store, "@alice:example.org", "org.example.app.ios", "abc123");

            THEN("the pusher is a single row carrying the upserted fields, per the spec's same app_id/pushkey rule")
            {
                REQUIRE(store.pushers.size() == 1U);
                REQUIRE(stored.has_value());
                REQUIRE(stored->app_display_name == "Example App v2");
                REQUIRE(stored->device_display_name == "iPhone 15");
                REQUIRE(stored->profile_tag == "xyz");
                REQUIRE(stored->lang == "en-US");
                REQUIRE(stored->data_format == "event_id_only");
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements[0].name == "upsert_pusher");
                REQUIRE(store.prepared_statements[1].name == "upsert_pusher");
            }
        }

        WHEN("alice registers two distinct pushers and one is deleted")
        {
            REQUIRE(merovingian::database::store_pusher(
                store, {"@alice:example.org", "org.example.app.ios", "abc123", "http", "Example App", "iPhone", "",
                        "en", "https://push.example.org/_matrix/push/v1/notify", ""}));
            REQUIRE(merovingian::database::store_pusher(store, {"@alice:example.org", "m.email", "alice@example.org",
                                                                "email", "Example App", "Email", "", "en", "", ""}));

            auto const deleted =
                merovingian::database::delete_pusher(store, "@alice:example.org", "org.example.app.ios", "abc123");
            auto const remaining = merovingian::database::list_pushers_for_user(store, "@alice:example.org");
            auto const redelete =
                merovingian::database::delete_pusher(store, "@alice:example.org", "org.example.app.ios", "abc123");

            THEN("only the deleted pusher is removed and re-deleting fails closed")
            {
                REQUIRE(deleted);
                REQUIRE_FALSE(redelete);
                REQUIRE(remaining.size() == 1U);
                REQUIRE(remaining.front().app_id == "m.email");
                REQUIRE(store.prepared_statements.back().name == "delete_pusher");
                REQUIRE_FALSE(
                    merovingian::database::find_pusher(store, "@alice:example.org", "org.example.app.ios", "abc123")
                        .has_value());
            }
        }

        WHEN("pushers for two different users are stored")
        {
            REQUIRE(merovingian::database::store_pusher(
                store, {"@alice:example.org", "org.example.app.ios", "abc123", "http", "Example App", "iPhone", "",
                        "en", "https://push.example.org/_matrix/push/v1/notify", ""}));
            REQUIRE(merovingian::database::store_pusher(
                store, {"@bob:example.org", "org.example.app.android", "def456", "http", "Example App", "Pixel", "",
                        "en", "https://push.example.org/_matrix/push/v1/notify", ""}));

            auto const alice_pushers = merovingian::database::list_pushers_for_user(store, "@alice:example.org");
            auto const bob_pushers = merovingian::database::list_pushers_for_user(store, "@bob:example.org");
            auto const ghost_pushers = merovingian::database::list_pushers_for_user(store, "@ghost:example.org");

            THEN("each user's pusher list is scoped to that user only")
            {
                REQUIRE(alice_pushers.size() == 1U);
                REQUIRE(bob_pushers.size() == 1U);
                REQUIRE(ghost_pushers.empty());
                REQUIRE(alice_pushers.front().user_id == "@alice:example.org");
                REQUIRE(bob_pushers.front().user_id == "@bob:example.org");
            }
        }

        WHEN("a pusher is registered with custom data_extra_json members and later updated")
        {
            // PR #479 review finding P1: the pushers table only stored
            // data_url/data_format, so any other custom member of the
            // pusher's `data` dictionary was discarded at registration time,
            // before it could ever reach the gateway. data_extra_json closes
            // that gap; this proves it survives a store round trip.
            REQUIRE(merovingian::database::store_pusher(
                store, {"@alice:example.org", "org.example.app.ios", "abc123", "http", "Example App", "iPhone", "",
                        "en", "https://push.example.org/_matrix/push/v1/notify", "event_id_only",
                        R"({"routing_key":"custom-routing-value"})"}));

            auto const stored =
                merovingian::database::find_pusher(store, "@alice:example.org", "org.example.app.ios", "abc123");

            THEN("the extra data survives the round trip intact")
            {
                REQUIRE(stored.has_value());
                REQUIRE(stored->data_extra_json == R"({"routing_key":"custom-routing-value"})");
            }

            AND_WHEN("the same (user_id, app_id, pushkey) is re-registered with different extra data")
            {
                REQUIRE(merovingian::database::store_pusher(
                    store, {"@alice:example.org", "org.example.app.ios", "abc123", "http", "Example App", "iPhone", "",
                            "en", "https://push.example.org/_matrix/push/v1/notify", "event_id_only",
                            R"({"routing_key":"replaced-value"})"}));
                auto const updated =
                    merovingian::database::find_pusher(store, "@alice:example.org", "org.example.app.ios", "abc123");

                THEN("the row is a single upserted entry carrying the new extra data")
                {
                    REQUIRE(store.pushers.size() == 1U);
                    REQUIRE(updated.has_value());
                    REQUIRE(updated->data_extra_json == R"({"routing_key":"replaced-value"})");
                }
            }
        }

        WHEN("a pusher is registered without specifying data_extra_json")
        {
            REQUIRE(merovingian::database::store_pusher(
                store, {"@alice:example.org", "org.example.app.ios", "abc123", "http", "Example App", "iPhone", "",
                        "en", "https://push.example.org/_matrix/push/v1/notify", ""}));

            auto const stored =
                merovingian::database::find_pusher(store, "@alice:example.org", "org.example.app.ios", "abc123");

            THEN("it defaults to empty, meaning no extra members")
            {
                REQUIRE(stored.has_value());
                REQUIRE(stored->data_extra_json.empty());
            }
        }

        WHEN("the pusher helpers receive input missing a required key")
        {
            auto const empty_user = merovingian::database::store_pusher(
                store, {"", "org.example.app.ios", "abc123", "http", "Example App", "iPhone", "", "en", "", ""});
            auto const empty_app_id = merovingian::database::store_pusher(
                store, {"@alice:example.org", "", "abc123", "http", "Example App", "iPhone", "", "en", "", ""});
            auto const empty_pushkey =
                merovingian::database::store_pusher(store, {"@alice:example.org", "org.example.app.ios", "", "http",
                                                            "Example App", "iPhone", "", "en", "", ""});
            auto const empty_kind =
                merovingian::database::store_pusher(store, {"@alice:example.org", "org.example.app.ios", "abc123", "",
                                                            "Example App", "iPhone", "", "en", "", ""});
            auto const missing =
                merovingian::database::find_pusher(store, "@ghost:example.org", "org.example.app.ios", "abc123");

            THEN("the store fails closed without synthesizing a partial pusher row")
            {
                REQUIRE_FALSE(empty_user);
                REQUIRE_FALSE(empty_app_id);
                REQUIRE_FALSE(empty_pushkey);
                REQUIRE_FALSE(empty_kind);
                REQUIRE_FALSE(missing.has_value());
                REQUIRE(store.pushers.empty());
            }
        }
    }
}
