// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/key_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto store_with_alice_keys() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    store.device_keys.push_back(
        {"@alice:remote.example.org", "DEVICE1", R"({"device_id":"DEVICE1","keys":{"ed25519:DEVICE1":"key-one"}})"});
    store.device_keys.push_back(
        {"@alice:remote.example.org", "DEVICE2", R"({"device_id":"DEVICE2","keys":{"ed25519:DEVICE2":"key-two"}})"});
    store.cross_signing_keys.push_back(
        {"@alice:remote.example.org", "master", R"({"usage":["master"],"keys":{"ed25519:master":"mk"}})"});
    store.cross_signing_keys.push_back(
        {"@alice:remote.example.org", "self_signing", R"({"usage":["self_signing"],"keys":{"ed25519:ssk":"sk"}})"});
    return store;
}

} // namespace

SCENARIO("Federation device-key query returns published device and cross-signing keys",
         "[federation][keys][query]")
{
    GIVEN("a store with two devices and cross-signing keys for a user")
    {
        auto const store = store_with_alice_keys();

        WHEN("an all-devices query is built")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(
                store, R"({"device_keys":{"@alice:remote.example.org":[]}})");

            THEN("both devices and the cross-signing keys appear in the response")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("DEVICE1") != std::string::npos);
                REQUIRE(body.find("DEVICE2") != std::string::npos);
                REQUIRE(body.find("master_keys") != std::string::npos);
                REQUIRE(body.find("self_signing_keys") != std::string::npos);
            }
        }

        WHEN("a query restricted to one device is built")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(
                store, R"({"device_keys":{"@alice:remote.example.org":["DEVICE1"]}})");

            THEN("only the requested device appears")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("DEVICE1") != std::string::npos);
                REQUIRE(body.find("DEVICE2") == std::string::npos);
            }
        }

        WHEN("a malformed request body is supplied")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(store, "not json");

            THEN("an empty string signals the malformed request")
            {
                REQUIRE(body.empty());
            }
        }
    }
}

SCENARIO("Federation one-time-key claim consumes and returns a stored key", "[federation][keys][claim]")
{
    GIVEN("a store holding one one-time key for a device")
    {
        auto store = merovingian::database::PersistentStore{};
        store.one_time_keys.push_back(
            {"@alice:remote.example.org", "DEVICE1", "signed_curve25519:AAAABBBB", R"({"key":"otk-payload"})"});

        WHEN("the key is claimed")
        {
            auto const body = merovingian::federation::build_one_time_keys_claim_response(
                store, R"({"one_time_keys":{"@alice:remote.example.org":{"DEVICE1":"signed_curve25519"}}})");

            THEN("the response carries the key and the store no longer holds it")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("signed_curve25519:AAAABBBB") != std::string::npos);
                REQUIRE(body.find("otk-payload") != std::string::npos);
                REQUIRE(store.one_time_keys.empty());
            }
        }
    }
}

SCENARIO("Federation user-devices query lists a user's published devices", "[federation][keys][devices]")
{
    GIVEN("a store with devices for a user")
    {
        auto const store = store_with_alice_keys();

        WHEN("the user's devices are queried")
        {
            auto const body =
                merovingian::federation::build_user_devices_response(store, "@alice:remote.example.org");

            THEN("the response carries the user id, both devices, and the master key")
            {
                REQUIRE_FALSE(body.empty());
                REQUIRE(body.find("@alice:remote.example.org") != std::string::npos);
                REQUIRE(body.find("DEVICE1") != std::string::npos);
                REQUIRE(body.find("DEVICE2") != std::string::npos);
                REQUIRE(body.find("master_key") != std::string::npos);
            }
        }

        WHEN("a user with no devices is queried")
        {
            auto const body =
                merovingian::federation::build_user_devices_response(store, "@nobody:remote.example.org");

            THEN("an empty string signals no published devices")
            {
                REQUIRE(body.empty());
            }
        }
    }
}
