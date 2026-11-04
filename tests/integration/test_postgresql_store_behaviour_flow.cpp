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
