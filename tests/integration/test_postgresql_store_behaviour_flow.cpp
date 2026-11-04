// SPDX-License-Identifier: GPL-3.0-or-later

// PostgreSQL behaviour of the persistent store that is backend-specific: statements whose SQL is
// written by hand, writes that must commit together, upserts and deletes, and what a reopened store
// loads back. Each scenario writes through the public store API, closes the store, opens a new one
// on the same database and asserts the loaded state. A scenario skips, visibly, when
// MEROVINGIAN_TEST_POSTGRESQL_URI is not set; a skip is not a pass.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <merovingian/database/persistent_store.hpp>
#include <merovingian/database/postgresql_store.hpp>

namespace
{

namespace db = merovingian::database;

[[nodiscard]] auto postgresql_uri() -> std::string
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string{} : std::string{value};
}

// A suffix that differs between scenarios and between processes, because the live database outlives
// a run and the rows of an earlier run must not collide with this one's primary keys.
[[nodiscard]] auto unique_suffix() -> std::string
{
    static auto const base = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    static auto counter = std::uint64_t{0U};
    return "pgb-" + std::to_string(base) + "-" + std::to_string(counter++);
}

[[nodiscard]] auto reopen(std::string const& uri) -> db::PersistentStoreOpenResult
{
    auto reopened = db::open_postgresql_persistent_store(uri);
    REQUIRE(reopened.ok);
    return reopened;
}

[[nodiscard]] auto make_user(db::PersistentStore& store, std::string const& user_id) -> bool
{
    return db::store_user(store, {user_id, "hash:pg-behaviour", false, false, false});
}

} // namespace

SCENARIO("PostgreSQL one-time keys are claimed once and the claim survives a reopen",
         "[database][postgresql][integration][pg-behaviour]")
{
    GIVEN("a user with a device holding two signed_curve25519 keys and one curve25519 key")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@otk-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));
        REQUIRE(db::store_device(opened.store, {user_id, "DEV", "phone"}));
        REQUIRE(db::store_one_time_key(opened.store, {user_id, "DEV", "signed_curve25519:A", R"({"key":"a"})"}));
        REQUIRE(db::store_one_time_key(opened.store, {user_id, "DEV", "signed_curve25519:B", R"({"key":"b"})"}));
        REQUIRE(db::store_one_time_key(opened.store, {user_id, "DEV", "curve25519:C", R"({"key":"c"})"}));

        WHEN("the same key id is stored again with new JSON, both signed keys are claimed, and the store is reopened")
        {
            REQUIRE(db::store_one_time_key(opened.store, {user_id, "DEV", "signed_curve25519:A", R"({"key":"a2"})"}));
            auto const first = db::claim_one_time_key(opened.store, user_id, "DEV", "signed_curve25519");
            auto const second = db::claim_one_time_key(opened.store, user_id, "DEV", "signed_curve25519");
            auto const third = db::claim_one_time_key(opened.store, user_id, "DEV", "signed_curve25519");
            opened = {};
            auto reopened = reopen(uri);
            auto const remaining =
                std::ranges::count_if(reopened.store.one_time_keys, [&user_id](db::PersistentOneTimeKey const& key) {
                    return key.user_id == user_id;
                });
            auto const again = db::claim_one_time_key(reopened.store, user_id, "DEV", "signed_curve25519");

            THEN("each key was handed out once, the upsert replaced the JSON, and only the unclaimed key remains")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                REQUIRE_FALSE(third.has_value());
                REQUIRE(first->key_id != second->key_id);
                auto const claimed_a = first->key_id == "signed_curve25519:A" ? *first : *second;
                REQUIRE(claimed_a.json == R"({"key":"a2"})");
                REQUIRE(remaining == 1);
                REQUIRE_FALSE(again.has_value());
                REQUIRE(db::claim_one_time_key(reopened.store, user_id, "DEV", "curve25519").has_value());
            }
        }
    }
}

SCENARIO("PostgreSQL keeps one fallback key per algorithm and drops a device's keys with the device",
         "[database][postgresql][integration][pg-behaviour][transaction]")
{
    GIVEN("a device with a fallback key, a one-time key, and a second device")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@fallback-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));
        REQUIRE(db::store_device(opened.store, {user_id, "ONE", ""}));
        REQUIRE(db::store_device(opened.store, {user_id, "TWO", ""}));
        REQUIRE(db::store_fallback_key(opened.store, {user_id, "ONE", "signed_curve25519:F1", R"({"k":1})"}));
        REQUIRE(db::store_one_time_key(opened.store, {user_id, "ONE", "signed_curve25519:O1", R"({"k":2})"}));
        REQUIRE(db::store_fallback_key(opened.store, {user_id, "TWO", "signed_curve25519:G1", R"({"k":3})"}));

        WHEN("a second fallback key of the same algorithm replaces the first and device ONE is deleted")
        {
            REQUIRE(db::store_fallback_key(opened.store, {user_id, "TWO", "signed_curve25519:G2", R"({"k":4})"}));
            REQUIRE(db::store_fallback_key(opened.store, {user_id, "ONE", "signed_curve25519:F2", R"({"k":5})"}));
            REQUIRE(db::delete_device(opened.store, user_id, "ONE"));
            opened = {};
            auto reopened = reopen(uri);
            auto const fallback_ids = [&](std::string_view device_id) {
                auto ids = std::vector<std::string>{};
                for (auto const& key : reopened.store.fallback_keys)
                {
                    if (key.user_id == user_id && key.device_id == device_id)
                    {
                        ids.push_back(key.key_id);
                    }
                }
                return ids;
            };

            THEN("device TWO keeps only its newest fallback key and device ONE has no device, no fallback, no OTK")
            {
                REQUIRE(fallback_ids("TWO") == std::vector<std::string>{"signed_curve25519:G2"});
                REQUIRE(fallback_ids("ONE").empty());
                REQUIRE(
                    std::ranges::none_of(reopened.store.one_time_keys, [&user_id](db::PersistentOneTimeKey const& key) {
                        return key.user_id == user_id && key.device_id == "ONE";
                    }));
                auto const device_ids = [&] {
                    auto ids = std::vector<std::string>{};
                    for (auto const& device : reopened.store.devices)
                    {
                        if (device.user_id == user_id)
                        {
                            ids.push_back(device.device_id);
                        }
                    }
                    return ids;
                }();
                REQUIRE(device_ids == std::vector<std::string>{"TWO"});
            }
        }
    }
}

SCENARIO("PostgreSQL login tokens are single use across a reopen", "[database][postgresql][integration][pg-behaviour]")
{
    GIVEN("a user with one valid login token and one that has already expired")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@login-" + suffix + ":example.org";
        auto const valid_hash = "token-hash:v2:valid-" + suffix;
        auto const expired_hash = "token-hash:v2:expired-" + suffix;
        REQUIRE(make_user(opened.store, user_id));
        auto const now = std::chrono::system_clock::now();
        REQUIRE(db::store_login_token(opened.store, {user_id, valid_hash, now + std::chrono::minutes{5}, false}));
        REQUIRE(db::store_login_token(opened.store, {user_id, expired_hash, now - std::chrono::minutes{5}, false}));

        WHEN("the valid token is redeemed, then the store is reopened and both are presented again")
        {
            auto const first = db::consume_login_token(opened.store, {valid_hash});
            opened = {};
            auto reopened = reopen(uri);
            auto const replay = db::consume_login_token(reopened.store, {valid_hash});
            auto const stale = db::consume_login_token(reopened.store, {expired_hash});

            THEN("the first redemption named the user and neither token can be redeemed from the new store")
            {
                REQUIRE(first.has_value());
                REQUIRE(*first == user_id);
                REQUIRE_FALSE(replay.has_value());
                REQUIRE_FALSE(stale.has_value());
            }
        }
    }
}

SCENARIO("PostgreSQL stores a device and its access token in one transaction",
         "[database][postgresql][integration][pg-behaviour][transaction]")
{
    GIVEN("a user with no devices")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@session-" + suffix + ":example.org";
        auto const token_hash = "token-hash:v2:session-" + suffix;
        REQUIRE(make_user(opened.store, user_id));

        WHEN("a login stores the device and the token together and the store is reopened")
        {
            auto const commits_before = db::committed_transaction_count(opened.store);
            REQUIRE(db::store_device_and_access_token(opened.store, db::PersistentDevice{user_id, "SESSION", "laptop"},
                                                      {user_id, "SESSION", token_hash, false, std::nullopt, {}}));
            auto const commits = db::committed_transaction_count(opened.store) - commits_before;
            opened = {};
            auto reopened = reopen(uri);

            THEN("the pair cost one commit and both rows loaded back")
            {
                REQUIRE(commits == 1U);
                auto const device = std::ranges::find_if(reopened.store.devices, [&](db::PersistentDevice const& row) {
                    return row.user_id == user_id && row.device_id == "SESSION";
                });
                REQUIRE(device != reopened.store.devices.end());
                REQUIRE(device->display_name == "laptop");
                auto const token =
                    std::ranges::find_if(reopened.store.access_tokens, [&](db::PersistentAccessToken const& row) {
                        return row.token_hash == token_hash;
                    });
                REQUIRE(token != reopened.store.access_tokens.end());
                REQUIRE(token->user_id == user_id);
                REQUIRE(token->device_id == "SESSION");
                REQUIRE_FALSE(token->revoked);
            }
        }

        WHEN("the token is revoked and the store is reopened")
        {
            REQUIRE(db::store_device_and_access_token(opened.store, db::PersistentDevice{user_id, "SESSION", ""},
                                                      {user_id, "SESSION", token_hash, false, std::nullopt, {}}));
            REQUIRE(db::revoke_access_token(opened.store, token_hash) == 1U);
            opened = {};
            auto reopened = reopen(uri);

            THEN("the revocation was written to the database")
            {
                auto const token =
                    std::ranges::find_if(reopened.store.access_tokens, [&](db::PersistentAccessToken const& row) {
                        return row.token_hash == token_hash;
                    });
                REQUIRE((token == reopened.store.access_tokens.end() || token->revoked));
            }
        }
    }
}

SCENARIO("PostgreSQL retained federation PDUs are inserted, updated and removed durably",
         "[database][postgresql][integration][pg-behaviour]")
{
    GIVEN("a retained PDU")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const event_id = "$deferred-" + suffix + ":example.org";
        auto const room_id = "!deferred-" + suffix + ":example.org";
        auto pdu = db::PersistentDeferredPdu{
            event_id, room_id, "origin.example", R"({"type":"m.room.message","prev_events":["$missing:example.org"]})",
            1000,     1U};
        REQUIRE(db::upsert_deferred_pdu(opened.store, pdu) == db::DeferredPduUpsert::inserted);

        WHEN("it is upserted again with new attempts and a different origin, then the store is reopened")
        {
            auto changed = pdu;
            changed.attempts = 4U;
            changed.origin = "other.example";
            changed.received_at_ms = 9999;
            REQUIRE(db::upsert_deferred_pdu(opened.store, changed) == db::DeferredPduUpsert::updated);
            opened = {};
            auto reopened = reopen(uri);
            auto const rows = db::deferred_pdus_for_room(reopened.store, room_id);

            THEN("one row loaded, with the new attempts and origin and the first receipt time")
            {
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front().attempts == 4U);
                REQUIRE(rows.front().origin == "other.example");
                REQUIRE(rows.front().received_at_ms == 1000);
                REQUIRE(rows.front().pdu_json == pdu.pdu_json);
            }
        }

        WHEN("it is removed and the store is reopened")
        {
            REQUIRE(db::remove_deferred_pdu(opened.store, event_id));
            REQUIRE_FALSE(db::remove_deferred_pdu(opened.store, event_id));
            opened = {};
            auto reopened = reopen(uri);

            THEN("it is gone from the database")
            {
                REQUIRE(db::deferred_pdus_for_room(reopened.store, room_id).empty());
            }
        }
    }
}

SCENARIO("PostgreSQL client transaction IDs keep the first result and age out to-device records in SQL",
         "[database][postgresql][integration][pg-behaviour]")
{
    GIVEN("a room send and a to-device send recorded by the same user")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@txn-" + suffix + ":example.org";
        auto const room_id = "!txn-" + suffix + ":example.org";
        REQUIRE(db::store_client_txn(opened.store,
                                     {user_id, room_id, "m.room.message", "t1", "$first:example.org", "DEV", 5U}));
        REQUIRE(db::store_client_txn(opened.store, {user_id, "", "m.to_device", "t2", "", "DEV", 10U}));
        REQUIRE(db::store_client_txn(opened.store, {user_id, "", "m.to_device", "t3", "", "DEV", 5000U}));

        WHEN("the room send is recorded again with another event ID, another device sends the same ID, "
             "to-device records older than 100 ms are pruned, and the store is reopened")
        {
            REQUIRE(db::store_client_txn(opened.store,
                                         {user_id, room_id, "m.room.message", "t1", "$second:example.org", "DEV", 6U}));
            REQUIRE(db::store_client_txn(opened.store,
                                         {user_id, room_id, "m.room.message", "t1", "$other:example.org", "DEV2", 7U}));
            auto const pruned = db::prune_to_device_client_txns(opened.store, 100U);
            opened = {};
            auto reopened = reopen(uri);

            THEN("the original result stands, the other device has its own, and only the old to-device record went")
            {
                REQUIRE(pruned == 1U);
                REQUIRE(db::find_client_txn_event_id(reopened.store, user_id, "DEV", room_id, "m.room.message", "t1") ==
                        std::optional<std::string>{"$first:example.org"});
                REQUIRE(db::find_client_txn_event_id(reopened.store, user_id, "DEV2", room_id, "m.room.message",
                                                     "t1") == std::optional<std::string>{"$other:example.org"});
                REQUIRE_FALSE(
                    db::find_client_txn_event_id(reopened.store, user_id, "DEV", "", "m.to_device", "t2").has_value());
                REQUIRE(
                    db::find_client_txn_event_id(reopened.store, user_id, "DEV", "", "m.to_device", "t3").has_value());
            }
        }
    }
}

SCENARIO("PostgreSQL pushers and room aliases are replaced in place and deleted durably",
         "[database][postgresql][integration][pg-behaviour]")
{
    GIVEN("a pusher and a room alias")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@push-" + suffix + ":example.org";
        auto const alias = "#alias-" + suffix + ":example.org";
        auto const room_id = "!alias-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));
        REQUIRE(db::store_room(opened.store, {room_id, user_id}));
        auto pusher = db::PersistentPusher{user_id,
                                           "app.example",
                                           "key-1",
                                           "http",
                                           "App",
                                           "Phone",
                                           "tag-1",
                                           "en",
                                           "https://push.example/_matrix/push/v1/notify",
                                           "event_id_only",
                                           R"({"extra":1})",
                                           "DEV"};
        REQUIRE(db::store_pusher(opened.store, pusher));
        REQUIRE(db::store_room_alias(opened.store, {alias, room_id, user_id}));

        WHEN("the pusher is stored again with changed fields and the store is reopened")
        {
            pusher.lang = "fr";
            pusher.data_extra_json = R"({"extra":2})";
            pusher.device_display_name = "Tablet";
            REQUIRE(db::store_pusher(opened.store, pusher));
            opened = {};
            auto reopened = reopen(uri);
            auto const rows = db::list_pushers_for_user(reopened.store, user_id);

            THEN("one pusher loaded, carrying the changed fields")
            {
                REQUIRE(rows.size() == 1U);
                REQUIRE(rows.front().lang == "fr");
                REQUIRE(rows.front().data_extra_json == R"({"extra":2})");
                REQUIRE(rows.front().device_display_name == "Tablet");
                REQUIRE(rows.front().device_id == "DEV");
            }
        }

        WHEN("the pusher and the alias are deleted and the store is reopened")
        {
            REQUIRE(db::delete_pusher(opened.store, user_id, "app.example", "key-1"));
            REQUIRE(db::delete_room_alias(opened.store, alias));
            opened = {};
            auto reopened = reopen(uri);

            THEN("neither loads back")
            {
                REQUIRE(db::list_pushers_for_user(reopened.store, user_id).empty());
                REQUIRE_FALSE(db::find_room_alias(reopened.store, alias).has_value());
            }
        }

        WHEN("only the store is reopened")
        {
            opened = {};
            auto reopened = reopen(uri);
            auto const found = db::find_room_alias(reopened.store, alias);

            THEN("the alias loads with its room and creator")
            {
                REQUIRE(found.has_value());
                REQUIRE(found->room_id == room_id);
                REQUIRE(found->creator_user_id == user_id);
            }
        }
    }
}

SCENARIO("PostgreSQL account state changes and invites are upserted and survive a reopen",
         "[database][postgresql][integration][pg-behaviour]")
{
    GIVEN("a user and an invite to a room")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@account-" + suffix + ":example.org";
        auto const room_id = "!invite-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));
        auto invite = db::PersistentInvite{room_id,
                                           user_id,
                                           "@inviter:example.org",
                                           "$invite1:example.org",
                                           R"({"type":"m.room.member"})",
                                           {R"({"type":"m.room.name"})"},
                                           7U,
                                           ""};
        REQUIRE(db::upsert_invite(opened.store, invite));

        WHEN("the password changes, the account is deactivated, the invite is upserted again, and the store reopens")
        {
            REQUIRE(db::update_user_password(opened.store, user_id, "hash:changed"));
            REQUIRE(db::set_user_deactivated(opened.store, user_id));
            invite.event_id = "$invite2:example.org";
            invite.invite_state_events_json = {R"({"type":"m.room.name"})", R"({"type":"m.room.topic"})"};
            invite.stream_ordering = 9U;
            REQUIRE(db::upsert_invite(opened.store, invite));
            opened = {};
            auto reopened = reopen(uri);
            auto const user = std::ranges::find_if(reopened.store.users, [&](db::PersistentUser const& row) {
                return row.user_id == user_id;
            });
            auto const loaded = db::find_invite(reopened.store, room_id, user_id);

            THEN("the account is changed and closed, and one invite loaded with its latest event and state list")
            {
                REQUIRE(user != reopened.store.users.end());
                REQUIRE(user->password_hash == "hash:changed");
                REQUIRE(user->deactivated);
                REQUIRE(loaded.has_value());
                REQUIRE(loaded->event_id == "$invite2:example.org");
                REQUIRE(loaded->stream_ordering == 9U);
                REQUIRE(loaded->invite_state_events_json == invite.invite_state_events_json);
                REQUIRE(std::ranges::count_if(reopened.store.invites, [&](db::PersistentInvite const& row) {
                            return row.room_id == room_id && row.user_id == user_id;
                        }) == 1);
            }
        }

        WHEN("the invite is deleted and the store is reopened")
        {
            REQUIRE(db::delete_invite(opened.store, room_id, user_id));
            opened = {};
            auto reopened = reopen(uri);

            THEN("it does not load back")
            {
                REQUIRE_FALSE(db::find_invite(reopened.store, room_id, user_id).has_value());
            }
        }
    }
}

SCENARIO("PostgreSQL receipts are upserted per key and removed durably",
         "[database][postgresql][integration][pg-behaviour]")
{
    GIVEN("a read receipt in a room")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@receipt-" + suffix + ":example.org";
        auto const room_id = "!receipt-" + suffix + ":example.org";
        auto receipt = db::PersistentReceipt{room_id, "m.read", user_id, "$one:example.org", 100U, 0U, ""};
        REQUIRE(db::store_receipt(opened.store, receipt));

        WHEN("the same key moves to a later event and the store is reopened")
        {
            receipt.event_id = "$two:example.org";
            receipt.ts = 200U;
            REQUIRE(db::store_receipt(opened.store, receipt));
            opened = {};
            auto reopened = reopen(uri);
            auto const rows = std::ranges::count_if(reopened.store.receipts, [&](db::PersistentReceipt const& row) {
                return row.room_id == room_id && row.user_id == user_id;
            });
            auto const row = std::ranges::find_if(reopened.store.receipts, [&](db::PersistentReceipt const& r) {
                return r.room_id == room_id && r.user_id == user_id;
            });

            THEN("one receipt loaded, on the later event")
            {
                REQUIRE(rows == 1);
                REQUIRE(row->event_id == "$two:example.org");
                REQUIRE(row->ts == 200U);
            }
        }

        WHEN("it is removed and the store is reopened")
        {
            REQUIRE(db::remove_receipt(opened.store, receipt));
            opened = {};
            auto reopened = reopen(uri);

            THEN("no receipt loads for the key")
            {
                REQUIRE(std::ranges::none_of(reopened.store.receipts, [&](db::PersistentReceipt const& row) {
                    return row.room_id == room_id && row.user_id == user_id;
                }));
            }
        }
    }
}

// ---- Appservice delivery state, identity data, key backup, sync data, rooms, moderation ----

namespace
{

// Milliseconds since the epoch as a time point, so a value written to a millisecond column reads back equal.
[[nodiscard]] auto at_ms(std::int64_t ms) -> std::chrono::system_clock::time_point
{
    return std::chrono::system_clock::time_point{std::chrono::milliseconds{ms}};
}

[[nodiscard]] auto future_ms() -> std::int64_t
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               (std::chrono::system_clock::now() + std::chrono::hours{24}).time_since_epoch())
        .count();
}

} // namespace

SCENARIO("PostgreSQL appservice cursor, outbox and directory survive a reopen and a completed delivery",
         "[database][postgresql][integration][pg-behaviour][appservice]")
{
    GIVEN("an application service with a pending transaction, three queued events and two directory entries")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const as_id = "bridge-" + suffix;
        REQUIRE(db::store_appservice_txn_cursor(opened.store, {as_id, 5U, 40U, 6U, 41U}));
        for (auto const ordering : {41U, 42U, 43U})
        {
            REQUIRE(db::enqueue_appservice_event(
                opened.store, {as_id, ordering, "$as-" + std::to_string(ordering) + "-" + suffix + ":example.org"}));
        }
        REQUIRE(db::set_appservice_directory_entry(opened.store, {as_id, "net-a", "!dir-a-" + suffix + ":example.org"},
                                                   true));
        REQUIRE(db::set_appservice_directory_entry(opened.store, {as_id, "net-b", "!dir-b-" + suffix + ":example.org"},
                                                   true));

        WHEN("the store is reopened")
        {
            opened = {};
            auto reopened = reopen(uri);
            auto const cursor = db::find_appservice_txn_cursor(reopened.store, as_id);

            THEN("the cursor, the three queued events in order and both directory entries loaded")
            {
                REQUIRE(cursor.next_txn_id == 5U);
                REQUIRE(cursor.delivered_stream_ordering == 40U);
                REQUIRE(cursor.pending_txn_id == 6U);
                REQUIRE(cursor.pending_stream_ordering == 41U);
                REQUIRE(db::count_appservice_outbox_entries(reopened.store, as_id) == 3U);
                auto const first = db::find_first_appservice_outbox_entry(reopened.store, as_id);
                REQUIRE(first.has_value());
                REQUIRE(first->stream_ordering == 41U);
                REQUIRE(std::ranges::count_if(reopened.store.appservice_directory,
                                              [&](db::PersistentAppserviceDirectoryEntry const& row) {
                                                  return row.appservice_id == as_id;
                                              }) == 2);
            }
        }

        WHEN("the pending transaction is completed, one directory entry is unlisted, and the store is reopened")
        {
            REQUIRE(db::complete_appservice_delivery(opened.store, as_id, 41U));
            REQUIRE(db::set_appservice_directory_entry(opened.store,
                                                       {as_id, "net-a", "!dir-a-" + suffix + ":example.org"}, false));
            opened = {};
            auto reopened = reopen(uri);
            auto const cursor = db::find_appservice_txn_cursor(reopened.store, as_id);
            auto const first = db::find_first_appservice_outbox_entry(reopened.store, as_id);

            THEN("the cursor advanced and cleared in the database, the delivered row is gone, and one entry remains")
            {
                REQUIRE(cursor.delivered_stream_ordering == 41U);
                REQUIRE(cursor.pending_txn_id == 0U);
                REQUIRE(cursor.pending_stream_ordering == 0U);
                REQUIRE(db::count_appservice_outbox_entries(reopened.store, as_id) == 2U);
                REQUIRE(first.has_value());
                REQUIRE(first->stream_ordering == 42U);
                REQUIRE(std::ranges::count_if(reopened.store.appservice_directory,
                                              [&](db::PersistentAppserviceDirectoryEntry const& row) {
                                                  return row.appservice_id == as_id;
                                              }) == 1);
                REQUIRE(std::ranges::any_of(reopened.store.appservice_directory,
                                            [&](db::PersistentAppserviceDirectoryEntry const& row) {
                                                return row.appservice_id == as_id && row.network_id == "net-b";
                                            }));
            }
        }
    }
}

SCENARIO("PostgreSQL third-party IDs, filters, OpenID and refresh tokens keep their fields across a reopen",
         "[database][postgresql][integration][pg-behaviour][identity]")
{
    GIVEN("a user with a device")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@identity-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));
        REQUIRE(db::store_device(opened.store, {user_id, "DEV", ""}));
        auto const address = "alice-" + suffix + "@example.org";

        WHEN("a third-party ID is stored unbound, stored again bound with its optional fields, and a second is deleted")
        {
            REQUIRE(db::store_account_threepid(opened.store, {user_id, "email", address, std::nullopt, std::nullopt,
                                                              100U, 0U, false, "secret", "sid1"}));
            REQUIRE(db::store_account_threepid(opened.store, {user_id, "email", address, std::string{"GB"},
                                                              std::string{"id.example.org"}, 100U, 250U, true,
                                                              std::nullopt, std::nullopt}));
            REQUIRE(db::store_account_threepid(opened.store, {user_id, "msisdn", "4477" + suffix, std::nullopt,
                                                              std::nullopt, 1U, 0U, false, "s", "x"}));
            REQUIRE(db::delete_account_threepid(opened.store, user_id, "msisdn", "4477" + suffix));
            opened = {};
            auto reopened = reopen(uri);
            auto const bindings =
                std::ranges::count_if(reopened.store.account_threepids, [&](db::PersistentThreePidBinding const& row) {
                    return row.user_id == user_id;
                });
            auto const found = db::find_account_threepid(reopened.store, user_id, "email", address);

            THEN("one binding loaded, carrying the second write's values, and the deleted one did not")
            {
                REQUIRE(bindings == 1);
                REQUIRE(found.has_value());
                REQUIRE(found->bound);
                REQUIRE(found->validated_at_ms == 250U);
                REQUIRE(found->added_at_ms == 100U);
                REQUIRE(found->country == std::optional<std::string>{"GB"});
                REQUIRE(found->id_server == std::optional<std::string>{"id.example.org"});
            }
        }

        WHEN("filters, an OpenID token and two refresh tokens are stored and one refresh token is revoked")
        {
            REQUIRE(db::store_filter(opened.store, {user_id, "f1", R"({"room":{"timeline":{"limit":5}}})"}));
            REQUIRE(db::store_filter(opened.store, {user_id, "f2", R"({"presence":{"not_types":["m.presence"]}})"}));
            auto const expiry = future_ms();
            REQUIRE(db::store_openid_token(opened.store, {user_id, "token-hash:v2:openid-a-" + suffix, at_ms(expiry)}));
            REQUIRE(db::store_openid_token(opened.store, {user_id, "token-hash:v2:openid-b-" + suffix, at_ms(expiry)}));
            REQUIRE(db::store_refresh_token(
                opened.store, {user_id, "DEV", "token-hash:v2:refresh-1-" + suffix, false, at_ms(expiry), ""}));
            REQUIRE(db::store_refresh_token(opened.store, {user_id, "DEV", "token-hash:v2:refresh-2-" + suffix, false,
                                                           std::nullopt, "token-hash:v2:refresh-1-" + suffix}));
            REQUIRE(db::revoke_refresh_token(opened.store, "token-hash:v2:refresh-1-" + suffix) == 1U);
            opened = {};
            auto reopened = reopen(uri);
            auto const refresh = [&](std::string const& tag) {
                auto const row =
                    std::ranges::find_if(reopened.store.refresh_tokens, [&](db::PersistentRefreshToken const& r) {
                        return r.token_hash == "token-hash:v2:refresh-" + tag + "-" + suffix;
                    });
                REQUIRE(row != reopened.store.refresh_tokens.end());
                return *row;
            };
            auto const first = refresh("1");
            auto const second = refresh("2");
            auto const openid_tokens =
                std::ranges::count_if(reopened.store.openid_tokens, [&](db::PersistentOpenidToken const& row) {
                    return row.user_id == user_id;
                });

            THEN("both filters, both OpenID tokens and both refresh tokens loaded with their expiry, flag and parent")
            {
                REQUIRE(db::find_filter(reopened.store, user_id, "f1")->json == R"({"room":{"timeline":{"limit":5}}})");
                REQUIRE(db::find_filter(reopened.store, user_id, "f2").has_value());
                REQUIRE(openid_tokens == 2);
                REQUIRE(first.revoked);
                REQUIRE(first.expires_at.has_value());
                REQUIRE(*first.expires_at == at_ms(expiry));
                REQUIRE_FALSE(second.revoked);
                REQUIRE_FALSE(second.expires_at.has_value());
                REQUIRE(second.predecessor_hash == "token-hash:v2:refresh-1-" + suffix);
            }
        }

        WHEN("the user's OpenID tokens are revoked and the store is reopened")
        {
            REQUIRE(db::store_openid_token(opened.store,
                                           {user_id, "token-hash:v2:openid-c-" + suffix, at_ms(future_ms())}));
            REQUIRE(db::revoke_openid_tokens_for_user(opened.store, user_id));
            opened = {};
            auto reopened = reopen(uri);

            THEN("none loads back")
            {
                REQUIRE(std::ranges::none_of(reopened.store.openid_tokens, [&](db::PersistentOpenidToken const& row) {
                    return row.user_id == user_id;
                }));
            }
        }
    }
}

SCENARIO("PostgreSQL key backup versions and sessions are deleted at the right scope",
         "[database][postgresql][integration][pg-behaviour][key-backup]")
{
    GIVEN("a user with two backup versions and sessions in two rooms")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@backup-" + suffix + ":example.org";
        auto const room_a = "!ba-" + suffix + ":example.org";
        auto const room_b = "!bb-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));
        REQUIRE(db::create_key_backup_version(opened.store, user_id, R"({"algorithm":"a"})") ==
                std::optional<std::string>{"1"});
        REQUIRE(db::create_key_backup_version(opened.store, user_id, R"({"algorithm":"b"})") ==
                std::optional<std::string>{"2"});
        for (auto const& [room, session] : {
                 std::pair{room_a, "s1"},
                 {room_a, "s2"},
                 {room_b, "s3"}
        })
        {
            REQUIRE(db::store_key_backup_session(opened.store, {user_id, "1", room, session, R"({"k":1})"}));
        }
        REQUIRE(db::store_key_backup_session(opened.store, {user_id, "2", room_a, "s9", R"({"k":9})"}));
        auto const sessions_of = [&](db::PersistentStore const& store, std::string_view version) {
            return std::ranges::count_if(store.key_backup_sessions, [&](db::PersistentKeyBackupSession const& row) {
                return row.user_id == user_id && row.version == version;
            });
        };

        WHEN("one session, then one room's sessions, are deleted and the store is reopened")
        {
            REQUIRE(db::delete_key_backup_session(opened.store, user_id, "1", room_a, "s1"));
            opened = {};
            auto reopened = reopen(uri);
            auto const after_session = sessions_of(reopened.store, "1");
            REQUIRE(db::delete_key_backup_room_sessions(reopened.store, user_id, "1", room_a));
            auto again = reopen(uri);

            THEN("each delete took exactly its scope and left the other version alone")
            {
                REQUIRE(after_session == 2);
                REQUIRE(sessions_of(reopened.store, "1") == 1);
                reopened = {};
                REQUIRE(sessions_of(again.store, "1") == 1);
                REQUIRE(sessions_of(again.store, "2") == 1);
            }
        }

        WHEN("all of a version's sessions are deleted and the store is reopened")
        {
            REQUIRE(db::delete_all_key_backup_sessions(opened.store, user_id, "1"));
            opened = {};
            auto reopened = reopen(uri);

            THEN("version 1 keeps its row but no sessions, and version 2 keeps its session")
            {
                REQUIRE(sessions_of(reopened.store, "1") == 0);
                REQUIRE(sessions_of(reopened.store, "2") == 1);
                REQUIRE(std::ranges::count_if(reopened.store.key_backup_versions,
                                              [&](db::PersistentKeyBackupVersion const& row) {
                                                  return row.user_id == user_id;
                                              }) == 2);
            }
        }

        WHEN("version 1 is deleted and the store is reopened")
        {
            REQUIRE(db::delete_key_backup_version(opened.store, user_id, "1"));
            opened = {};
            auto reopened = reopen(uri);

            THEN("the version and its sessions are gone, version 2 remains, and version numbers are not reused")
            {
                REQUIRE(sessions_of(reopened.store, "1") == 0);
                REQUIRE(std::ranges::none_of(reopened.store.key_backup_versions,
                                             [&](db::PersistentKeyBackupVersion const& row) {
                                                 return row.user_id == user_id && row.version == "1";
                                             }));
                REQUIRE(sessions_of(reopened.store, "2") == 1);
                REQUIRE(db::create_key_backup_version(reopened.store, user_id, R"({"algorithm":"c"})") ==
                        std::optional<std::string>{"3"});
            }
        }
    }
}

SCENARIO("PostgreSQL presence and capped account data keep their numbers and flags across a reopen",
         "[database][postgresql][integration][pg-behaviour][sync-data]")
{
    GIVEN("a user with presence and account data")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@syncdata-" + suffix + ":example.org";
        auto const room_id = "!syncdata-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));

        WHEN("presence is upserted twice and the store is reopened")
        {
            REQUIRE(db::upsert_presence(opened.store, {0U, user_id, "online", "first", 10, true, 0}));
            REQUIRE(db::upsert_presence(opened.store, {0U, user_id, "unavailable", "second", 4200, false, 0}));
            opened = {};
            auto reopened = reopen(uri);
            auto const rows =
                std::ranges::count_if(reopened.store.presence_states, [&](db::PersistentPresence const& row) {
                    return row.user_id == user_id;
                });
            auto const row = std::ranges::find_if(reopened.store.presence_states, [&](db::PersistentPresence const& r) {
                return r.user_id == user_id;
            });

            THEN("one row loaded with the second write's state, number, flag and a stream position")
            {
                REQUIRE(rows == 1);
                REQUIRE(row->presence == "unavailable");
                REQUIRE(row->status_msg == "second");
                REQUIRE(row->last_active_ago == 4200);
                REQUIRE_FALSE(row->currently_active);
                REQUIRE(row->stream_id > 0U);
            }
        }

        WHEN("global account data fills a cap of two types, a third is refused, and a held type is updated")
        {
            auto const put = [&](std::string const& type, std::string const& content) {
                return db::store_global_account_data_within_cap(opened.store, {user_id, "", type, content, 0U}, 2U);
            };
            REQUIRE(put("org.a", R"({"v":1})") == db::CappedAccountDataStore::stored);
            REQUIRE(put("org.b", R"({"v":1})") == db::CappedAccountDataStore::stored);
            auto const refused = put("org.c", R"({"v":1})");
            REQUIRE(put("org.a", R"({"v":2})") == db::CappedAccountDataStore::stored);
            opened = {};
            auto reopened = reopen(uri);

            THEN("the refusal wrote nothing and the update replaced the content")
            {
                REQUIRE(refused == db::CappedAccountDataStore::over_cap);
                REQUIRE(db::find_account_data_content(reopened.store, user_id, "", "org.a") ==
                        std::optional<std::string>{R"({"v":2})"});
                REQUIRE(db::find_account_data_content(reopened.store, user_id, "", "org.b").has_value());
                REQUIRE_FALSE(db::find_account_data_content(reopened.store, user_id, "", "org.c").has_value());
            }
        }

        WHEN("room account data fills a cap of one type and a second type is refused")
        {
            auto const put = [&](std::string const& type) {
                return db::store_room_account_data_within_cap(opened.store, {user_id, room_id, type, R"({"v":1})", 0U},
                                                              1U);
            };
            REQUIRE(put("org.tag") == db::CappedAccountDataStore::stored);
            auto const refused = put("org.other");
            opened = {};
            auto reopened = reopen(uri);

            THEN("only the first type loaded")
            {
                REQUIRE(refused == db::CappedAccountDataStore::over_cap);
                REQUIRE(db::find_account_data_content(reopened.store, user_id, room_id, "org.tag").has_value());
                REQUIRE_FALSE(db::find_account_data_content(reopened.store, user_id, room_id, "org.other").has_value());
            }
        }
    }
}

SCENARIO("PostgreSQL rooms, memberships and profiles are updated in place and survive a reopen",
         "[database][postgresql][integration][pg-behaviour][rooms]")
{
    GIVEN("a user and a room created together with the creator's membership")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@roomer-" + suffix + ":example.org";
        auto const other_id = "@other-" + suffix + ":example.org";
        auto const room_id = "!roomer-" + suffix + ":example.org";
        REQUIRE(make_user(opened.store, user_id));
        REQUIRE(make_user(opened.store, other_id));
        auto const commits_before = db::committed_transaction_count(opened.store);
        REQUIRE(
            db::store_room_with_membership(opened.store, {room_id, user_id, false}, {room_id, user_id, "join", 3U}));
        auto const commits = db::committed_transaction_count(opened.store) - commits_before;

        WHEN("the room goes public, a second user joins and leaves, and the profile is created then edited")
        {
            REQUIRE(db::set_room_directory_public(opened.store, room_id, true));
            REQUIRE(db::store_membership(opened.store, {room_id, other_id, "invite", 4U}) ==
                    db::MembershipStoreResult::stored);
            REQUIRE(db::update_membership(opened.store, room_id, other_id, "join", 5U));
            REQUIRE(db::update_membership(opened.store, room_id, other_id, "leave", 6U));
            REQUIRE(db::store_profile(opened.store, {user_id, "Alice", "mxc://example.org/a"}));
            REQUIRE(db::update_profile_displayname(opened.store, user_id, "Alice B"));
            REQUIRE(db::update_profile_avatar_url(opened.store, user_id, "mxc://example.org/b"));
            opened = {};
            auto reopened = reopen(uri);
            auto const room = std::ranges::find_if(reopened.store.rooms, [&](db::PersistentRoom const& row) {
                return row.room_id == room_id;
            });
            auto const other =
                std::ranges::find_if(reopened.store.memberships, [&](db::PersistentMembership const& row) {
                    return row.room_id == room_id && row.user_id == other_id;
                });
            auto const profile = db::find_profile(reopened.store, user_id);

            THEN("room and creator membership cost one commit, and the later states loaded")
            {
                REQUIRE(commits == 1U);
                REQUIRE(room != reopened.store.rooms.end());
                REQUIRE(room->creator_user_id == user_id);
                REQUIRE(room->directory_public);
                REQUIRE(other != reopened.store.memberships.end());
                REQUIRE(other->membership == "leave");
                REQUIRE(other->stream_ordering == 6U);
                REQUIRE(profile.has_value());
                REQUIRE(profile->displayname == "Alice B");
                REQUIRE(profile->avatar_url == "mxc://example.org/b");
            }
        }

        WHEN("the second user's membership is deleted and the store is reopened")
        {
            REQUIRE(db::store_membership(opened.store, {room_id, other_id, "join", 4U}) ==
                    db::MembershipStoreResult::stored);
            REQUIRE(db::delete_membership(opened.store, room_id, other_id));
            opened = {};
            auto reopened = reopen(uri);

            THEN("only the creator's membership loads")
            {
                REQUIRE(std::ranges::count_if(reopened.store.memberships, [&](db::PersistentMembership const& row) {
                            return row.room_id == room_id;
                        }) == 1);
            }
        }
    }
}

SCENARIO("PostgreSQL policy rules, media state and membership projections change durably",
         "[database][postgresql][integration][pg-behaviour][moderation]")
{
    GIVEN("a policy rule, an uploaded file and a room with a member")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto const suffix = unique_suffix();
        auto const user_id = "@moderated-" + suffix + ":example.org";
        auto const room_id = "!moderated-" + suffix + ":example.org";
        auto const media_id = "moderated-" + suffix;
        REQUIRE(make_user(opened.store, user_id));
        REQUIRE(db::store_room(opened.store, {room_id, user_id, false}));
        REQUIRE(db::store_policy_rule(opened.store, {"rule-a-" + suffix, "server", "bad.example", "ban", "spam"}));
        REQUIRE(db::store_policy_rule(opened.store, {"rule-b-" + suffix, "user", "@x:bad.example", "ban", "abuse"}));
        REQUIRE(db::store_local_media(opened.store, {media_id, user_id, "image/png", 77U, "sha256", "digest-" + suffix,
                                                     false, false, true, "a.png"}));

        WHEN("one rule is deleted, the media is quarantined and then removed, and the store is reopened")
        {
            REQUIRE(db::delete_policy_rule(opened.store, "rule-a-" + suffix));
            REQUIRE(db::update_local_media_state(opened.store, media_id, true, false));
            auto const after_quarantine =
                std::ranges::find_if(opened.store.local_media, [&](db::PersistentLocalMedia const& m) {
                    return m.media_id == media_id;
                })->quarantined;
            REQUIRE(db::update_local_media_state(opened.store, media_id, true, true));
            opened = {};
            auto reopened = reopen(uri);
            auto const media = std::ranges::find_if(reopened.store.local_media, [&](db::PersistentLocalMedia const& m) {
                return m.media_id == media_id;
            });

            THEN("one rule loaded, and the media carries both flags, its size and its upload name")
            {
                REQUIRE(after_quarantine);
                REQUIRE(std::ranges::count_if(reopened.store.policy_rules, [&](db::PersistentPolicyRule const& rule) {
                            return rule.rule_id.ends_with(suffix);
                        }) == 1);
                REQUIRE(media != reopened.store.local_media.end());
                REQUIRE(media->quarantined);
                REQUIRE(media->removed);
                REQUIRE(media->size_bytes == 77U);
                REQUIRE(media->upload_name == "a.png");
                REQUIRE(media->legacy_endpoint_visible);
            }
        }

        WHEN("a membership projection with an invite is stored and the store is reopened")
        {
            auto invite = db::PersistentInvite{room_id,
                                               user_id,
                                               "@inviter:example.org",
                                               "$proj-" + suffix + ":example.org",
                                               R"({"type":"m.room.member"})",
                                               {R"({"type":"m.room.name"})"},
                                               12U,
                                               ""};
            REQUIRE(db::store_membership_projection(opened.store, room_id, {user_id, "invite", 12U, invite}));
            opened = {};
            auto reopened = reopen(uri);
            auto const member =
                std::ranges::find_if(reopened.store.memberships, [&](db::PersistentMembership const& row) {
                    return row.room_id == room_id && row.user_id == user_id;
                });

            THEN("the membership and the invite both loaded")
            {
                REQUIRE(member != reopened.store.memberships.end());
                REQUIRE(member->membership == "invite");
                REQUIRE(member->stream_ordering == 12U);
                auto const loaded = db::find_invite(reopened.store, room_id, user_id);
                REQUIRE(loaded.has_value());
                REQUIRE(loaded->stream_ordering == 12U);
                REQUIRE(loaded->event_id == "$proj-" + suffix + ":example.org");
            }
        }
    }
}

// ---- Every table the store hydrates ----

namespace
{

// The first element of `rows` satisfying `matches`, or nullptr. For asserting that a hydrated collection holds a
// row without depending on the order the database returned it in.
template <typename Rows, typename Predicate>
[[nodiscard]] auto row_where(Rows const& rows, Predicate matches) -> typename Rows::value_type const*
{
    auto const found = std::ranges::find_if(rows, matches);
    return found == rows.end() ? nullptr : &*found;
}

} // namespace

SCENARIO("PostgreSQL hydrates a row of every table the store loads, with its numeric and boolean columns",
         "[database][postgresql][integration][pg-behaviour][hydration]")
{
    GIVEN("one row written to every hydrated table through the store API")
    {
        auto const uri = postgresql_uri();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto opened = reopen(uri);
        auto& store = opened.store;
        auto const s = unique_suffix();
        auto const user = "@hyd-" + s + ":example.org";
        auto const other = "@hyd-other-" + s + ":example.org";
        auto const room = "!hyd-" + s + ":example.org";
        auto const e1 = "$hyd-1-" + s + ":example.org";
        auto const e2 = "$hyd-2-" + s + ":example.org";
        auto const server = "hyd-" + s + ".example.org";
        auto const expiry = future_ms();
        auto const access_hash = "token-hash:v2:hyd-access-" + s;
        auto const refresh_hash = "token-hash:v2:hyd-refresh-" + s;
        auto const login_hash = "token-hash:v2:hyd-login-" + s;
        auto const openid_hash = "token-hash:v2:hyd-openid-" + s;

        // accounts and sessions
        REQUIRE(db::store_user(store, {user, "hash:hyd", true, true, true}));
        REQUIRE(make_user(store, other));
        REQUIRE(db::store_device(store, {user, "DEV", "phone"}));
        REQUIRE(db::store_access_token(store, {user, "DEV", access_hash, true, at_ms(expiry), "pred-" + s}));
        REQUIRE(db::store_refresh_token(store, {user, "DEV", refresh_hash, true, at_ms(expiry), "pred-" + s}));
        REQUIRE(db::store_login_token(store, {user, login_hash, at_ms(expiry), false}));
        REQUIRE(db::store_openid_token(store, {user, openid_hash, at_ms(expiry)}));
        REQUIRE(db::store_profile(store, {user, "Hyd", "mxc://example.org/hyd"}));
        REQUIRE(db::store_filter(store, {user, "flt", R"({"limit":3})"}));
        REQUIRE(db::store_account_threepid(store, {user, "email", "hyd-" + s + "@example.org", std::string{"GB"},
                                                   std::string{"id.example.org"}, 11U, 22U, true, std::string{"cs"},
                                                   std::string{"sid"}}));
        REQUIRE(db::store_pusher(store, {user, "app", "pk", "http", "App", "Dev", "tag", "en", "https://p.example/n",
                                         "event_id_only", R"({"a":1})", "DEV"}));
        // federation
        REQUIRE(db::store_server_signing_key(
            store, {server, "ed25519:hyd", "cHVi", 4102444800000U, "secretbox:v1:QUJDREVGR0hJSktM"}));
        // A retired key never holds a secret and is valid only until it expired.
        auto retired_key = db::PersistentServerSigningKey{server, "ed25519:old", "b2xk", 4102444800000U, ""};
        retired_key.expired_ts = 4102444700000U;
        REQUIRE(db::store_server_signing_key(store, retired_key));
        REQUIRE(db::store_federation_destination(store, {server, "backoff", 500U, 600U, 7U}));
        REQUIRE(db::store_federation_transaction(
            store, {"txn-" + s, server, "PUT", "/send/1", "origin.example", "1234", R"({"pdus":[]})", 3U, 900U}));
        REQUIRE(db::upsert_deferred_pdu(store, {e2 + "-deferred", room, "origin.example", R"({"type":"m.x"})", 321,
                                                2U}) == db::DeferredPduUpsert::inserted);
        // rooms, events and the DAG
        REQUIRE(db::store_room_with_membership(store, {room, user, true}, {room, user, "join", 5U}));
        REQUIRE(db::upsert_invite(store, {room,
                                          other,
                                          user,
                                          "$inv-" + s + ":example.org",
                                          R"({"type":"m.room.member"})",
                                          {R"({"type":"m.room.name"})"},
                                          6U,
                                          "resident.example"}));
        REQUIRE(db::store_event_with_state(
            store, {e1, room, user, R"({"type":"m.room.create","state_key":""})", 1U, 10U, {}, {}, {}},
            db::PersistentStateEvent{room, "m.room.create", "", e1}));
        REQUIRE(db::store_event(store, {e2,
                                        room,
                                        user,
                                        R"({"type":"m.room.message","content":{"body":"x"}})",
                                        2U,
                                        20U,
                                        {e1},
                                        {e1},
                                        {{server, "ed25519:hyd", "c2ln"}}}));
        REQUIRE(db::set_event_status(store, e2, "soft_failed"));
        REQUIRE(db::update_forward_extremities(store, room, e2, {e1}, true));
        REQUIRE(db::create_or_reuse_state_group(store, room, "sg-a-" + s, std::nullopt,
                                                {
                                                    {"sg-a-" + s, "m.room.create", "", e1}
        })
                    .has_value());
        REQUIRE(db::create_or_reuse_state_group(
                    store, room, "sg-b-" + s, "sg-a-" + s,
                    {
                        {"sg-b-" + s, "m.room.create", "", e1},
                        {"sg-b-" + s, "m.room.name",   "", e2}
        })
                    .has_value());
        REQUIRE(db::set_event_state_group(store, e2, "sg-b-" + s));
        REQUIRE(db::store_room_alias(store, {"#hyd-" + s + ":example.org", room, user}));
        REQUIRE(db::store_client_txn(store, {user, room, "m.room.message", "tx", e2, "DEV", 77U}));
        // encryption keys and backups
        REQUIRE(db::store_device_key(store, {user, "DEV", R"({"keys":{}})"}));
        REQUIRE(db::store_one_time_key(store, {user, "DEV", "signed_curve25519:o", R"({"k":1})"}));
        REQUIRE(db::store_fallback_key(store, {user, "DEV", "signed_curve25519:f", R"({"k":2})"}));
        REQUIRE(db::store_cross_signing_key(store, {user, "master", R"({"usage":["master"]})"}));
        REQUIRE(db::store_key_signature(store, {user, user, "DEV", R"({"sig":1})"}));
        REQUIRE(db::create_key_backup_version(store, user, R"({"algorithm":"a"})") == std::optional<std::string>{"1"});
        REQUIRE(db::store_key_backup_session(store, {user, "1", room, "sess", R"({"k":3})"}));
        // media
        REQUIRE(db::store_local_media(
            store, {"hyd-media-" + s, user, "image/png", 99U, "sha256", "dig-" + s, true, true, false, "hyd.png"}));
        REQUIRE(db::commit_pending_media_upload(store, {"hyd-pending-" + s, user, 1000U, 2000U}, {}));
        REQUIRE(db::store_media_blob(store, {
                                                "blob-" + s, "sha256", "dig-" + s, 4U, std::string{"ab\0c", 4U},
                                                        3U
        }));
        REQUIRE(
            db::store_remote_media(store, {server, "hyd-remote-" + s, "image/gif", 55U, true, "local-" + s, 4242U}));
        // moderation and audit
        REQUIRE(db::append_audit_event(store, {"auth", "login", user, "DEV", "hyd " + s}));
        REQUIRE(db::append_admin_action(store, {user, "suspend", other}));
        REQUIRE(db::store_policy_rule(store, {"rule-" + s, "server", "bad.example", "ban", "spam"}));
        // sync data
        REQUIRE(db::store_account_data(store, {user, "", "org.hyd.global", R"({"g":1})", 0U}));
        REQUIRE(db::store_account_data(store, {user, room, "org.hyd.room", R"({"r":1})", 0U}));
        REQUIRE(db::enqueue_to_device_message(store, {0U, user, other, "OTHERDEV", "m.hyd", R"({"c":1})", 1500U}));
        REQUIRE(db::record_device_list_change(store, {0U, other, user, "left"}));
        REQUIRE(db::upsert_presence(store, {0U, user, "online", "hello", 31, true, 0}));
        REQUIRE(db::store_receipt(store, {room, "m.read", user, e2, 888U, 0U, "thread-1"}));
        REQUIRE(db::store_notification(store, {user, room, e2, 20U, 999U, R"(["notify"])", "tag", true}));
        // appservice
        REQUIRE(db::store_appservice_txn_cursor(store, {"as-" + s, 8U, 70U, 9U, 71U}));
        REQUIRE(db::enqueue_appservice_event(store, {"as-" + s, 72U, e2}));
        REQUIRE(db::set_appservice_directory_entry(store, {"as-" + s, "net", room}, true));
        auto const sync_watermark = store.next_sync_stream_id;
        // Milliseconds since the epoch rise from run to run, and the singleton only moves forward.
        auto const event_watermark = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        REQUIRE(db::persist_event_stream_watermark(store, event_watermark));

        WHEN("the store is reopened")
        {
            opened = {};
            auto reopened = reopen(uri);
            auto const& r = reopened.store;

            THEN("every collection holds its row with the values written, including numbers and flags")
            {
                // users
                auto const* loaded_user = row_where(r.users, [&](db::PersistentUser const& v) {
                    return v.user_id == user;
                });
                REQUIRE(loaded_user != nullptr);
                CHECK(loaded_user->locked);
                CHECK(loaded_user->suspended);
                CHECK(loaded_user->admin);
                CHECK_FALSE(loaded_user->deactivated);
                CHECK(loaded_user->password_hash == "hash:hyd");
                // devices, tokens
                CHECK(row_where(r.devices, [&](db::PersistentDevice const& v) {
                          return v.user_id == user && v.device_id == "DEV" && v.display_name == "phone";
                      }) != nullptr);
                auto const* access = row_where(r.access_tokens, [&](db::PersistentAccessToken const& v) {
                    return v.token_hash == access_hash;
                });
                REQUIRE(access != nullptr);
                CHECK(access->revoked);
                CHECK(access->expires_at == std::optional{at_ms(expiry)});
                CHECK(access->predecessor_refresh_hash == "pred-" + s);
                auto const* refresh = row_where(r.refresh_tokens, [&](db::PersistentRefreshToken const& v) {
                    return v.token_hash == refresh_hash;
                });
                REQUIRE(refresh != nullptr);
                CHECK(refresh->revoked);
                CHECK(refresh->expires_at == std::optional{at_ms(expiry)});
                auto const* login = row_where(r.login_tokens, [&](db::PersistentLoginToken const& v) {
                    return v.token_hash == login_hash;
                });
                REQUIRE(login != nullptr);
                CHECK_FALSE(login->used);
                CHECK(login->expires_at == at_ms(expiry));
                auto const* openid = row_where(r.openid_tokens, [&](db::PersistentOpenidToken const& v) {
                    return v.token_hash == openid_hash;
                });
                REQUIRE(openid != nullptr);
                CHECK(openid->expires_at == at_ms(expiry));
                // profiles, filters, third-party IDs, pushers
                CHECK(row_where(r.profiles, [&](db::PersistentProfile const& v) {
                          return v.user_id == user && v.displayname == "Hyd" && v.avatar_url == "mxc://example.org/hyd";
                      }) != nullptr);
                CHECK(row_where(r.filters, [&](db::PersistentFilter const& v) {
                          return v.user_id == user && v.filter_id == "flt" && v.json == R"({"limit":3})";
                      }) != nullptr);
                auto const* threepid = row_where(r.account_threepids, [&](db::PersistentThreePidBinding const& v) {
                    return v.user_id == user;
                });
                REQUIRE(threepid != nullptr);
                CHECK(threepid->bound);
                CHECK(threepid->added_at_ms == 11U);
                CHECK(threepid->validated_at_ms == 22U);
                CHECK(threepid->country == std::optional<std::string>{"GB"});
                CHECK(threepid->sid == std::optional<std::string>{"sid"});
                auto const* pusher = row_where(r.pushers, [&](db::PersistentPusher const& v) {
                    return v.user_id == user;
                });
                REQUIRE(pusher != nullptr);
                CHECK(pusher->data_url == "https://p.example/n");
                CHECK(pusher->data_extra_json == R"({"a":1})");
                CHECK(pusher->device_id == "DEV");
                // federation
                auto const* key = row_where(r.server_signing_keys, [&](db::PersistentServerSigningKey const& v) {
                    return v.server_name == server && v.key_id == "ed25519:hyd";
                });
                REQUIRE(key != nullptr);
                CHECK(key->valid_until_ts == 4102444800000U);
                CHECK(key->expired_ts == 0U);
                CHECK(key->secret_key == "secretbox:v1:QUJDREVGR0hJSktM");
                auto const* retired = row_where(r.server_signing_keys, [&](db::PersistentServerSigningKey const& v) {
                    return v.server_name == server && v.key_id == "ed25519:old";
                });
                REQUIRE(retired != nullptr);
                CHECK(retired->expired_ts == 4102444700000U);
                CHECK(retired->valid_until_ts == 4102444700000U);
                CHECK(retired->secret_key.empty());
                auto const* destination =
                    row_where(r.federation_destinations, [&](db::PersistentFederationDestination const& v) {
                        return v.server_name == server;
                    });
                REQUIRE(destination != nullptr);
                CHECK(destination->state == "backoff");
                CHECK(destination->retry_after_ts == 500U);
                CHECK(destination->last_success_ts == 600U);
                CHECK(destination->consecutive_failures == 7U);
                auto const* transaction =
                    row_where(r.federation_transactions, [&](db::PersistentFederationTransaction const& v) {
                        return v.transaction_id == "txn-" + s;
                    });
                REQUIRE(transaction != nullptr);
                CHECK(transaction->retry_count == 3U);
                CHECK(transaction->next_retry_ts == 900U);
                CHECK(transaction->body == R"({"pdus":[]})");
                auto const* deferred = row_where(r.deferred_pdus, [&](db::PersistentDeferredPdu const& v) {
                    return v.event_id == e2 + "-deferred";
                });
                REQUIRE(deferred != nullptr);
                CHECK(deferred->received_at_ms == 321);
                CHECK(deferred->attempts == 2U);
                // rooms, memberships, invites
                auto const* loaded_room = row_where(r.rooms, [&](db::PersistentRoom const& v) {
                    return v.room_id == room;
                });
                REQUIRE(loaded_room != nullptr);
                CHECK(loaded_room->directory_public);
                CHECK(loaded_room->creator_user_id == user);
                auto const* member = row_where(r.memberships, [&](db::PersistentMembership const& v) {
                    return v.room_id == room && v.user_id == user;
                });
                REQUIRE(member != nullptr);
                CHECK(member->stream_ordering == 5U);
                auto const* invite = row_where(r.invites, [&](db::PersistentInvite const& v) {
                    return v.room_id == room && v.user_id == other;
                });
                REQUIRE(invite != nullptr);
                CHECK(invite->stream_ordering == 6U);
                CHECK(invite->resident_server == "resident.example");
                CHECK(invite->invite_state_events_json.size() == 1U);
                // events, DAG tables, current state, forward extremities, state groups
                auto const second = r.events.find(e2);
                REQUIRE(second != r.events.end());
                CHECK(second->depth == 2U);
                CHECK(second->stream_ordering == 20U);
                CHECK(second->status == "soft_failed");
                CHECK(row_where(r.event_edges, [&](db::PersistentEventEdge const& v) {
                          return v.event_id == e2 && v.prev_event_id == e1;
                      }) != nullptr);
                CHECK(row_where(r.event_auth, [&](db::PersistentEventAuth const& v) {
                          return v.event_id == e2 && v.auth_event_id == e1;
                      }) != nullptr);
                CHECK(row_where(r.event_signatures, [&](db::PersistentEventSignature const& v) {
                          return v.event_id == e2 && v.server_name == server && v.signature == "c2ln";
                      }) != nullptr);
                CHECK(db::find_current_state_event_id(r, room, "m.room.create", "") == std::optional<std::string>{e1});
                CHECK(row_where(r.state_transitions, [&](db::PersistentStateTransition const& v) {
                          return v.room_id == room && v.event_id == e1;
                      }) != nullptr);
                CHECK(db::find_forward_extremities(r, room) == std::vector<std::string>{e2});
                auto const group_b = db::find_state_group(r, "sg-b-" + s);
                REQUIRE(group_b.has_value());
                CHECK(group_b->delta_depth == 1U);
                CHECK(group_b->parent_state_group_id == std::optional<std::string>{"sg-a-" + s});
                CHECK(db::find_event_state_group(r, e2) == std::optional<std::string>{"sg-b-" + s});
                auto const full_state = db::read_state_group_full_state(r, "sg-b-" + s);
                REQUIRE(full_state.has_value());
                CHECK(full_state->size() == 2U);
                CHECK(db::find_room_alias(r, "#hyd-" + s + ":example.org").has_value());
                CHECK(db::find_client_txn_event_id(r, user, "DEV", room, "m.room.message", "tx") ==
                      std::optional<std::string>{e2});
                CHECK(row_where(r.client_txn_ids, [&](db::PersistentClientTxnRecord const& v) {
                          return v.txn_id == "tx" && v.user_id == user && v.created_at_ms == 77U;
                      }) != nullptr);
                // encryption keys and backups
                CHECK(db::find_device_key(r, user, "DEV").has_value());
                CHECK(row_where(r.one_time_keys, [&](db::PersistentOneTimeKey const& v) {
                          return v.user_id == user && v.key_id == "signed_curve25519:o";
                      }) != nullptr);
                CHECK(db::find_fallback_key(r, user, "DEV", "signed_curve25519").has_value());
                CHECK(row_where(r.cross_signing_keys, [&](db::PersistentCrossSigningKey const& v) {
                          return v.user_id == user && v.key_type == "master";
                      }) != nullptr);
                CHECK(row_where(r.key_signatures, [&](db::PersistentKeySignature const& v) {
                          return v.signer_user_id == user && v.target_device_id == "DEV";
                      }) != nullptr);
                CHECK(row_where(r.key_backup_versions, [&](db::PersistentKeyBackupVersion const& v) {
                          return v.user_id == user && v.version == "1";
                      }) != nullptr);
                CHECK(row_where(r.key_backup_sessions, [&](db::PersistentKeyBackupSession const& v) {
                          return v.user_id == user && v.session_id == "sess";
                      }) != nullptr);
                CHECK(r.key_backup_version_high_water.contains(user));
                // media
                auto const* media = row_where(r.local_media, [&](db::PersistentLocalMedia const& v) {
                    return v.media_id == "hyd-media-" + s;
                });
                REQUIRE(media != nullptr);
                CHECK(media->size_bytes == 99U);
                CHECK(media->quarantined);
                CHECK(media->removed);
                CHECK_FALSE(media->legacy_endpoint_visible);
                CHECK(media->upload_name == "hyd.png");
                auto const* pending =
                    row_where(r.pending_media_uploads, [&](db::PersistentPendingMediaUpload const& v) {
                        return v.media_id == "hyd-pending-" + s;
                    });
                REQUIRE(pending != nullptr);
                CHECK(pending->created_at_ms == 1000U);
                CHECK(pending->expires_at_ms == 2000U);
                auto const* blob = row_where(r.media_blobs, [&](db::PersistentMediaBlob const& v) {
                    return v.storage_id == "blob-" + s;
                });
                REQUIRE(blob != nullptr);
                CHECK(blob->size_bytes == 4U);
                CHECK(blob->ref_count == 3U);
                auto const* remote = row_where(r.remote_media, [&](db::PersistentRemoteMedia const& v) {
                    return v.media_id == "hyd-remote-" + s;
                });
                REQUIRE(remote != nullptr);
                CHECK(remote->size_bytes == 55U);
                CHECK(remote->quarantined);
                CHECK(remote->fetched_at_ms == 4242U);
                CHECK(remote->local_media_id == "local-" + s);
                // audit, admin, policy
                CHECK(std::ranges::any_of(r.audit_log, [&](db::PersistentAuditEvent const& v) {
                    return v.event_type == "login" && v.reason == "hyd " + s;
                }));
                CHECK(row_where(r.admin_actions, [&](db::PersistentAdminAction const& v) {
                          return v.admin_user_id == user && v.action == "suspend" && v.target == other;
                      }) != nullptr);
                CHECK(row_where(r.policy_rules, [&](db::PersistentPolicyRule const& v) {
                          return v.rule_id == "rule-" + s && v.reason == "spam";
                      }) != nullptr);
                // sync data
                CHECK(db::find_account_data_content(r, user, "", "org.hyd.global") ==
                      std::optional<std::string>{R"({"g":1})"});
                CHECK(db::find_account_data_content(r, user, room, "org.hyd.room") ==
                      std::optional<std::string>{R"({"r":1})"});
                auto const* to_device = row_where(r.to_device_messages, [&](db::PersistentToDeviceMessage const& v) {
                    return v.target_user_id == other && v.message_type == "m.hyd";
                });
                REQUIRE(to_device != nullptr);
                CHECK(to_device->stream_id > 0U);
                CHECK(to_device->created_at_ms > 0U); // stamped by the store when written
                auto const* change = row_where(r.device_list_changes, [&](db::PersistentDeviceListChange const& v) {
                    return v.subject_user_id == user && v.observer_user_id == other;
                });
                REQUIRE(change != nullptr);
                CHECK(change->stream_id > 0U);
                CHECK(change->change_type == "left");
                auto const* presence = row_where(r.presence_states, [&](db::PersistentPresence const& v) {
                    return v.user_id == user;
                });
                REQUIRE(presence != nullptr);
                CHECK(presence->last_active_ago == 31);
                CHECK(presence->currently_active);
                auto const* receipt = row_where(r.receipts, [&](db::PersistentReceipt const& v) {
                    return v.room_id == room && v.user_id == user;
                });
                REQUIRE(receipt != nullptr);
                CHECK(receipt->ts == 888U);
                CHECK(receipt->thread_id == "thread-1");
                CHECK(receipt->stream_id > 0U);
                auto const notifications = db::list_notifications_for_user(r, user);
                REQUIRE(notifications.size() == 1U);
                CHECK(notifications.front().highlight);
                CHECK(notifications.front().ts == 999U);
                CHECK(notifications.front().stream_ordering == 20U);
                // appservice
                auto const cursor = db::find_appservice_txn_cursor(r, "as-" + s);
                CHECK(cursor.next_txn_id == 8U);
                CHECK(cursor.pending_stream_ordering == 71U);
                CHECK(db::count_appservice_outbox_entries(r, "as-" + s) == 1U);
                CHECK(row_where(r.appservice_directory, [&](db::PersistentAppserviceDirectoryEntry const& v) {
                          return v.appservice_id == "as-" + s && v.room_id == room;
                      }) != nullptr);
                // watermarks
                CHECK(r.next_sync_stream_id >= sync_watermark);
                CHECK(r.event_stream_watermark >= event_watermark);
            }
        }
    }
}
