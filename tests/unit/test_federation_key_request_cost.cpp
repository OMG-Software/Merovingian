// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit release gate (ADR-0604). POST /user/keys/claim and /user/keys/query accept any signed federated
// server and looped over every user and device the 1 MiB body named, scanning a whole key table for each entry
// under the runtime lock, and the answers to the queries this server sends did a linear search per key. Now a
// server answers only for its own users, an entry is an index lookup, a request over max_key_request_entries is
// refused whole, and the answer checks are set lookups. Cost is shown with the stores' rows-examined counters.

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreOpenResult.hpp"
#include "merovingian/federation/KeyQuery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace fed = merovingian::federation;

constexpr auto server = std::string_view{"example.org"};

[[nodiscard]] auto store_with_keys(std::size_t devices) -> db::PersistentStore
{
    auto opened = db::open_persistent_store();
    REQUIRE(opened.ok);
    auto store = std::move(opened.store);
    for (auto index = std::size_t{0U}; index < devices; ++index)
    {
        auto const user = "@real" + std::to_string(index) + ":example.org";
        REQUIRE(db::store_device(store, {user, "DEV", "name"}));
        REQUIRE(db::store_device_key(
            store, {user, "DEV", R"({"algorithms":[],"device_id":"DEV","keys":{},"user_id":")" + user + R"("})"}));
        REQUIRE(db::store_one_time_key(store, {user, "DEV", "signed_curve25519:K", R"({"key":"otk"})"}));
        REQUIRE(db::store_fallback_key(store, {user, "DEV", "signed_curve25519:F", R"({"key":"fb"})"}));
    }
    return store;
}

// {"<section>":{"@ghost0:<host>":<value>,...}} for `count` users.
[[nodiscard]] auto request_of(std::string_view section, std::size_t count, std::string_view host,
                              std::string_view value) -> std::string
{
    auto body = "{\"" + std::string{section} + "\":{";
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        if (index != 0U)
        {
            body += ",";
        }
        body += "\"@ghost" + std::to_string(index) + ":" + std::string{host} + "\":" + std::string{value};
    }
    return body + "}}";
}

} // namespace

SCENARIO("a one-time key claim for users that do not exist reads no key rows, however many keys the server holds",
         "[federation][keys][claim][adr-0604]")
{
    GIVEN("stores holding the keys of 30 and of 1500 devices, and a claim naming 2000 users that do not exist")
    {
        auto small = store_with_keys(30U);
        auto large = store_with_keys(1500U);
        auto const body = request_of("one_time_keys", 2000U, "example.org", R"({"DEV":"signed_curve25519"})");

        WHEN("the claim is built against each store")
        {
            auto const small_before = small.key_rows_examined.value();
            auto const small_response = fed::build_one_time_keys_claim_response(small, body, server);
            auto const small_rows = small.key_rows_examined.value() - small_before;
            auto const large_before = large.key_rows_examined.value();
            auto const large_response = fed::build_one_time_keys_claim_response(large, body, server);
            auto const large_rows = large.key_rows_examined.value() - large_before;

            THEN("neither read a row, and both answer an empty claim")
            {
                REQUIRE_FALSE(small_response.empty());
                REQUIRE(small_response == large_response);
                REQUIRE(small_rows == 0U);
                REQUIRE(large_rows == 0U);
            }
        }
    }

    GIVEN("a store and a claim naming 2000 users of another server")
    {
        auto store = store_with_keys(30U);
        auto const body = request_of("one_time_keys", 2000U, "elsewhere.example", R"({"DEV":"signed_curve25519"})");

        WHEN("the claim is built")
        {
            auto const before = store.key_rows_examined.value();
            auto const response = fed::build_one_time_keys_claim_response(store, body, server);

            THEN("no row is read, since another server's users are not this server's to hand keys for")
            {
                REQUIRE_FALSE(response.empty());
                REQUIRE(store.key_rows_examined.value() == before);
            }
        }
    }

    GIVEN("a store with three real devices and a claim naming them")
    {
        auto store = store_with_keys(3U);
        auto const body = std::string{R"({"one_time_keys":{"@real0:example.org":{"DEV":"signed_curve25519"},)"} +
                          R"("@real1:example.org":{"DEV":"signed_curve25519"},)" +
                          R"("@real2:example.org":{"DEV":"signed_curve25519"}}})";

        WHEN("the claim is built, then built again")
        {
            auto const first = fed::build_one_time_keys_claim_response(store, body, server);
            auto const second = fed::build_one_time_keys_claim_response(store, body, server);

            THEN("the first hands out each device's one-time key and the second falls back to the fallback keys")
            {
                REQUIRE(first.find("otk") != std::string::npos);
                REQUIRE(first.find("@real0:example.org") != std::string::npos);
                REQUIRE(first.find("@real2:example.org") != std::string::npos);
                REQUIRE(second.find("otk") == std::string::npos);
                REQUIRE(second.find("fb") != std::string::npos);
                REQUIRE(store.one_time_keys.empty());
            }
        }
    }
}

SCENARIO("a device-key query for users that do not exist reads no device rows, however many devices the server holds",
         "[federation][keys][query][adr-0604]")
{
    GIVEN("stores holding 30 and 1500 devices, and a query naming 2000 users that do not exist, and users elsewhere")
    {
        auto const small = store_with_keys(30U);
        auto const large = store_with_keys(1500U);
        auto const local_body = request_of("device_keys", 2000U, "example.org", "[]");
        auto const remote_body = request_of("device_keys", 2000U, "elsewhere.example", "[]");

        WHEN("each query is built against each store")
        {
            auto const small_before = small.device_table_rows_examined.value();
            auto const small_response = fed::build_device_keys_query_response(small, local_body, server);
            auto const small_rows = small.device_table_rows_examined.value() - small_before;
            auto const large_before = large.device_table_rows_examined.value();
            auto const large_response = fed::build_device_keys_query_response(large, local_body, server);
            auto const large_rows = large.device_table_rows_examined.value() - large_before;
            auto const remote_before = large.device_table_rows_examined.value();
            auto const remote_response = fed::build_device_keys_query_response(large, remote_body, server);
            auto const remote_rows = large.device_table_rows_examined.value() - remote_before;

            THEN("the cost does not grow with the table and another server's users cost nothing")
            {
                REQUIRE_FALSE(small_response.empty());
                REQUIRE(small_response == large_response);
                REQUIRE(small_rows == large_rows);
                REQUIRE(large_rows == 0U);
                REQUIRE_FALSE(remote_response.empty());
                REQUIRE(remote_rows == 0U);
            }
        }
    }

    GIVEN("a store with three real devices and a query naming them")
    {
        auto const store = store_with_keys(3U);
        auto const body = std::string{R"({"device_keys":{"@real0:example.org":[],"@real1:example.org":["DEV"],)"} +
                          R"("@real2:example.org":["NOPE"],"@away:elsewhere.example":[]}})";

        WHEN("the query is built")
        {
            auto const response = fed::build_device_keys_query_response(store, body, server);

            THEN("the named devices are published, an unnamed device is not, and a foreign user is not answered")
            {
                REQUIRE(response.find("@real0:example.org") != std::string::npos);
                REQUIRE(response.find("@real1:example.org") != std::string::npos);
                REQUIRE(response.find("@real2:example.org") == std::string::npos);
                REQUIRE(response.find("@away:elsewhere.example") == std::string::npos);
            }
        }
    }
}

SCENARIO("a key request is refused whole when it names more than the entry cap", "[federation][keys][adr-0604]")
{
    GIVEN("requests of exactly the cap and of one more, counted by users")
    {
        auto store = store_with_keys(1U);
        auto const at_cap_query = request_of("device_keys", fed::max_key_request_entries, "example.org", "[]");
        auto const over_cap_query = request_of("device_keys", fed::max_key_request_entries + 1U, "example.org", "[]");
        auto const at_cap_claim = request_of("one_time_keys", fed::max_key_request_entries, "example.org", "{}");
        auto const over_cap_claim = request_of("one_time_keys", fed::max_key_request_entries + 1U, "example.org", "{}");

        WHEN("each is checked and built")
        {
            THEN("the cap request is answered and the request over it is refused with an empty body")
            {
                REQUIRE_FALSE(fed::key_request_exceeds_entry_cap(at_cap_query, "device_keys"));
                REQUIRE(fed::key_request_exceeds_entry_cap(over_cap_query, "device_keys"));
                REQUIRE_FALSE(fed::key_request_exceeds_entry_cap(at_cap_claim, "one_time_keys"));
                REQUIRE(fed::key_request_exceeds_entry_cap(over_cap_claim, "one_time_keys"));
                REQUIRE_FALSE(fed::build_device_keys_query_response(store, at_cap_query, server).empty());
                REQUIRE(fed::build_device_keys_query_response(store, over_cap_query, server).empty());
                REQUIRE_FALSE(fed::build_one_time_keys_claim_response(store, at_cap_claim, server).empty());
                REQUIRE(fed::build_one_time_keys_claim_response(store, over_cap_claim, server).empty());
            }
        }
    }

    GIVEN("a claim whose users are few but whose devices push the entry count over the cap")
    {
        auto body = std::string{R"({"one_time_keys":{"@a:example.org":{)"};
        for (auto index = std::size_t{0U}; index < fed::max_key_request_entries; ++index)
        {
            body += (index == 0U ? "" : ",") + std::string{"\"D"} + std::to_string(index) + "\":\"signed_curve25519\"";
        }
        body += "}}}";

        WHEN("the entry cap is checked")
        {
            THEN("the devices count, so one user cannot carry the whole body")
            {
                REQUIRE(fed::key_request_exceeds_entry_cap(body, "one_time_keys"));
            }
        }
    }

    GIVEN("a body that does not parse")
    {
        THEN("it is not over the cap; the builders refuse it as malformed")
        {
            REQUIRE_FALSE(fed::key_request_exceeds_entry_cap("not json", "device_keys"));
        }
    }
}

SCENARIO("an answer from a remote server is checked against the users asked about with set lookups",
         "[federation][keys][remote][adr-0604]")
{
    GIVEN("a query for two users answered with 3000 users, a repeat, and cross-signing keys for unrequested users")
    {
        auto response = std::string{R"({"device_keys":{)"};
        for (auto index = 0; index < 3000; ++index)
        {
            auto const user = "@u" + std::to_string(index) + ":remote.example";
            response += (index == 0 ? "" : ",") + std::string{"\""} + user + R"(":{"D":{"user_id":")" + user +
                        R"(","device_id":"D"}})";
        }
        response += R"(},"master_keys":{"@u0:remote.example":{"user_id":"@u0:remote.example","usage":["master"],)";
        response += R"("keys":{"ed25519:m":"k"}},"@u2999:remote.example":{"user_id":"@u2999:remote.example",)";
        response += R"("usage":["master"],"keys":{"ed25519:m":"k"}}}})";
        auto const requested = std::vector<std::string>{"@u0:remote.example", "@u1:remote.example"};

        WHEN("the answer is accepted")
        {
            auto const accepted = fed::accept_remote_key_query_response("remote.example", response, requested);

            THEN("only the two requested users' devices and the requested user's master key are kept")
            {
                REQUIRE(accepted.has_value());
                REQUIRE(accepted->device_keys.size() == 2U);
                REQUIRE(accepted->master_keys.size() == 1U);
                REQUIRE(accepted->master_keys.front().key == "@u0:remote.example");
            }
        }
    }

    GIVEN("a claim for one user and device answered with an unasked user and an unasked device")
    {
        auto const response =
            std::string{R"({"one_time_keys":{"@a:remote.example":{"D":{"signed_curve25519:K":"v"},)"} +
            R"("OTHER":{"signed_curve25519:K":"v"}},"@b:remote.example":{"D":{"signed_curve25519:K":"v"}}}})";
        auto const requested = std::vector<std::pair<std::string, std::vector<std::string>>>{
            {"@a:remote.example", {"D"}}
        };

        WHEN("the answer is accepted")
        {
            auto const accepted = fed::accept_remote_key_claim_response("remote.example", response, requested);

            THEN("only the asked user and device remain")
            {
                REQUIRE(accepted.has_value());
                REQUIRE(accepted->one_time_keys.size() == 1U);
                REQUIRE(accepted->one_time_keys.front().key == "@a:remote.example");
            }
        }
    }
}
