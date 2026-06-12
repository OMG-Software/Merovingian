// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX FEDERATION KEY QUERY CONFORMANCE TESTS                   |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18                                   |
// |  URL:  ../../docs/matrix-v1.18-spec/server-server-api.md                 |
// |         #post_matrixfederationv1userkeysquery                           |
// |         #post_matrixfederationv1userkeyesclaim                          |
// |         #get_matrixfederationv1userdevicescircumflex                    |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE encodes a MUST from the Matrix spec. If a test fails:   |
// |    -> Fix the IMPLEMENTATION, not the assertion.                        |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
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

// Navigate a JSON object and return a pointer to the Value for `key`.
[[nodiscard]] auto json_get(merovingian::canonicaljson::Object const& obj, std::string const& key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& m : obj)
        if (m.key == key)
            return &(*m.value);
    return nullptr;
}

} // namespace

// --- POST /_matrix/federation/v1/user/keys/query -----------------------------
// Spec: ../../docs/matrix-v1.18-spec/server-server-api.md#post_matrixfederationv1userkeysquery
//
// Response MUST contain:
//   device_keys      - object mapping user IDs to device key maps
//   master_keys      - object mapping user IDs to cross-signing master keys
//   self_signing_keys - object mapping user IDs to self-signing keys
//   user_signing_keys - object mapping user IDs to user-signing keys (may be absent)
SCENARIO("Federation device-key query returns published device and cross-signing keys", "[federation][keys][query]")
{
    GIVEN("a store with two devices and cross-signing keys for a user")
    {
        auto const store = store_with_alice_keys();

        WHEN("an all-devices query is built")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(
                store, R"({"device_keys":{"@alice:remote.example.org":[]}})");

            THEN("the response parses to a JSON object with all required key maps")
            {
                REQUIRE_FALSE(body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: device_keys is an object mapping user IDs to device maps.
                auto const* dk_val = json_get(*root, std::string{"device_keys"});
                REQUIRE(dk_val != nullptr);
                auto const* dk_obj = std::get_if<merovingian::canonicaljson::Object>(&dk_val->storage());
                REQUIRE(dk_obj != nullptr);

                // Both devices must be present under alice's user ID.
                auto const* alice_val = json_get(*dk_obj, std::string{"@alice:remote.example.org"});
                REQUIRE(alice_val != nullptr);
                auto const* alice_obj = std::get_if<merovingian::canonicaljson::Object>(&alice_val->storage());
                REQUIRE(alice_obj != nullptr);
                REQUIRE(json_get(*alice_obj, std::string{"DEVICE1"}) != nullptr);
                REQUIRE(json_get(*alice_obj, std::string{"DEVICE2"}) != nullptr);

                // Spec MUST: master_keys is an object.
                auto const* mk_val = json_get(*root, std::string{"master_keys"});
                REQUIRE(mk_val != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&mk_val->storage()) != nullptr);

                // Spec MUST: self_signing_keys is an object.
                auto const* ssk_val = json_get(*root, std::string{"self_signing_keys"});
                REQUIRE(ssk_val != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&ssk_val->storage()) != nullptr);
            }
        }

        WHEN("a query restricted to one device is built")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(
                store, R"({"device_keys":{"@alice:remote.example.org":["DEVICE1"]}})");

            THEN("only the requested device appears under alice and DEVICE2 is absent")
            {
                REQUIRE_FALSE(body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* dk_val = json_get(*root, std::string{"device_keys"});
                REQUIRE(dk_val != nullptr);
                auto const* dk_obj = std::get_if<merovingian::canonicaljson::Object>(&dk_val->storage());
                REQUIRE(dk_obj != nullptr);
                auto const* alice_val = json_get(*dk_obj, std::string{"@alice:remote.example.org"});
                REQUIRE(alice_val != nullptr);
                auto const* alice_obj = std::get_if<merovingian::canonicaljson::Object>(&alice_val->storage());
                REQUIRE(alice_obj != nullptr);

                // Spec MUST: requested device present.
                REQUIRE(json_get(*alice_obj, std::string{"DEVICE1"}) != nullptr);
                // Spec MUST: unrequested device absent.
                REQUIRE(json_get(*alice_obj, std::string{"DEVICE2"}) == nullptr);
            }
        }

        WHEN("a malformed request body is supplied")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(store, "not json");

            THEN("an empty string signals the malformed request")
            {
                // Spec: malformed requests must not produce a partial response.
                REQUIRE(body.empty());
            }
        }

        WHEN("the request omits the required device_keys object")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(store, "{}");

            THEN("an empty string signals the malformed request")
            {
                REQUIRE(body.empty());
            }
        }

        WHEN("the request supplies a non-array device list")
        {
            auto const body = merovingian::federation::build_device_keys_query_response(
                store, R"({"device_keys":{"@alice:remote.example.org":{}}})");

            THEN("an empty string signals the malformed request")
            {
                REQUIRE(body.empty());
            }
        }
    }
}

// --- POST /_matrix/federation/v1/user/keys/claim -----------------------------
// Spec: ../../docs/matrix-v1.18-spec/server-server-api.md#post_matrixfederationv1userkeyesclaim
//
// Response MUST contain:
//   one_time_keys - object mapping user IDs → device IDs → key IDs → key objects
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

            THEN("the response contains the claimed key in the correct nested structure")
            {
                REQUIRE_FALSE(body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: one_time_keys is an object.
                auto const* otk_val = json_get(*root, std::string{"one_time_keys"});
                REQUIRE(otk_val != nullptr);
                auto const* otk_obj = std::get_if<merovingian::canonicaljson::Object>(&otk_val->storage());
                REQUIRE(otk_obj != nullptr);

                // one_time_keys["@alice"]["DEVICE1"] must be an object.
                auto const* alice_val = json_get(*otk_obj, std::string{"@alice:remote.example.org"});
                REQUIRE(alice_val != nullptr);
                auto const* alice_obj = std::get_if<merovingian::canonicaljson::Object>(&alice_val->storage());
                REQUIRE(alice_obj != nullptr);
                auto const* d1_val = json_get(*alice_obj, std::string{"DEVICE1"});
                REQUIRE(d1_val != nullptr);
                auto const* d1_obj = std::get_if<merovingian::canonicaljson::Object>(&d1_val->storage());
                REQUIRE(d1_obj != nullptr);

                // Spec MUST: the specific key ID is present as a key in the device map.
                REQUIRE(json_get(*d1_obj, std::string{"signed_curve25519:AAAABBBB"}) != nullptr);

                // The store must no longer hold the consumed key.
                REQUIRE(store.one_time_keys.empty());
            }
        }
    }
}

SCENARIO("Federation one-time-key claim falls back to a matching fallback key when no one-time key remains",
         "[federation][keys][claim]")
{
    GIVEN("a store holding only fallback keys for a device")
    {
        auto store = merovingian::database::PersistentStore{};
        store.fallback_keys.push_back(
            {"@alice:remote.example.org", "DEVICE1", "curve25519:WRONGALG", R"({"key":"wrong-alg"})"});
        store.fallback_keys.push_back(
            {"@alice:remote.example.org", "DEVICE1", "signed_curve25519:FALLBACK", R"({"key":"fallback-payload"})"});

        WHEN("a signed_curve25519 key is claimed over federation")
        {
            auto const body = merovingian::federation::build_one_time_keys_claim_response(
                store, R"({"one_time_keys":{"@alice:remote.example.org":{"DEVICE1":"signed_curve25519"}}})");

            THEN("the response returns the matching fallback key and leaves it reusable")
            {
                REQUIRE_FALSE(body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* otk_val = json_get(*root, std::string{"one_time_keys"});
                REQUIRE(otk_val != nullptr);
                auto const* otk_obj = std::get_if<merovingian::canonicaljson::Object>(&otk_val->storage());
                REQUIRE(otk_obj != nullptr);
                auto const* alice_val = json_get(*otk_obj, std::string{"@alice:remote.example.org"});
                REQUIRE(alice_val != nullptr);
                auto const* alice_obj = std::get_if<merovingian::canonicaljson::Object>(&alice_val->storage());
                REQUIRE(alice_obj != nullptr);
                auto const* d1_val = json_get(*alice_obj, std::string{"DEVICE1"});
                REQUIRE(d1_val != nullptr);
                auto const* d1_obj = std::get_if<merovingian::canonicaljson::Object>(&d1_val->storage());
                REQUIRE(d1_obj != nullptr);

                // Spec MUST: fallback keys are returned when no one-time keys remain.
                REQUIRE(json_get(*d1_obj, std::string{"signed_curve25519:FALLBACK"}) != nullptr);
                REQUIRE(json_get(*d1_obj, std::string{"curve25519:WRONGALG"}) == nullptr);

                // Spec MUST: fallback keys are reused until replaced, not consumed on claim.
                REQUIRE(store.fallback_keys.size() == 2U);
            }
        }

        WHEN("the request omits the required one_time_keys object")
        {
            auto const body = merovingian::federation::build_one_time_keys_claim_response(store, "{}");

            THEN("an empty string signals the malformed request")
            {
                REQUIRE(body.empty());
            }
        }

        WHEN("the request supplies a non-string algorithm entry")
        {
            auto const body = merovingian::federation::build_one_time_keys_claim_response(
                store, R"({"one_time_keys":{"@alice:remote.example.org":{"DEVICE1":{}}}})");

            THEN("an empty string signals the malformed request")
            {
                REQUIRE(body.empty());
            }
        }
    }
}

// --- GET /_matrix/federation/v1/user/devices/{userId} ------------------------
// Spec: ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixfederationv1userdevicescircumflex
//
// Response MUST contain:
//   user_id    - the queried user's fully-qualified Matrix ID
//   devices    - array of device objects
//   master_key - the user's cross-signing master key object (if published)
SCENARIO("Federation user-devices query lists a user's published devices", "[federation][keys][devices]")
{
    GIVEN("a store with devices for a user")
    {
        auto const store = store_with_alice_keys();

        WHEN("the user's devices are queried")
        {
            auto const body = merovingian::federation::build_user_devices_response(store, "@alice:remote.example.org");

            THEN("the response contains user_id, devices array, and master_key object")
            {
                REQUIRE_FALSE(body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: user_id is present and matches the queried user.
                auto const* uid_val = json_get(*root, std::string{"user_id"});
                REQUIRE(uid_val != nullptr);
                auto const* uid_str = std::get_if<std::string>(&uid_val->storage());
                REQUIRE(uid_str != nullptr);
                REQUIRE(*uid_str == "@alice:remote.example.org");

                // Spec MUST: devices is an array containing both published devices.
                auto const* devs_val = json_get(*root, std::string{"devices"});
                REQUIRE(devs_val != nullptr);
                auto const* devs_arr = std::get_if<merovingian::canonicaljson::Array>(&devs_val->storage());
                REQUIRE(devs_arr != nullptr);
                REQUIRE(devs_arr->size() == 2U);

                // Spec MUST: master_key is an object (when the user has published one).
                auto const* mk_val = json_get(*root, std::string{"master_key"});
                REQUIRE(mk_val != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&mk_val->storage()) != nullptr);
            }
        }

        WHEN("a user with no devices is queried")
        {
            auto const body = merovingian::federation::build_user_devices_response(store, "@nobody:remote.example.org");

            THEN("an empty string signals no published devices")
            {
                // Spec MUST: 404 M_NOT_FOUND for a user with no published device keys.
                // The HTTP handler converts the empty-string sentinel to 404.
                REQUIRE(body.empty());
            }
        }
    }
}

// Spec: stream_id MUST be a monotonically increasing integer so remote servers
// can detect gaps and schedule refetches when a device list changes.
// ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixfederationv1userdevicescircumflex
SCENARIO("Federation user-devices response reflects the store sync stream counter",
         "[federation][keys][devices]")
{
    GIVEN("a store with a device and a non-zero sync stream counter")
    {
        auto store = merovingian::database::PersistentStore{};
        store.device_keys.push_back({"@alice:example.org", "ALICE1", R"({"device_id":"ALICE1","keys":{}})"});
        store.next_sync_stream_id = 42U;

        WHEN("the user's devices are queried")
        {
            auto const body = merovingian::federation::build_user_devices_response(store, "@alice:example.org");

            THEN("stream_id in the response matches the store counter")
            {
                REQUIRE_FALSE(body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* sid_val = json_get(*root, std::string{"stream_id"});
                REQUIRE(sid_val != nullptr);
                auto const* sid_int = std::get_if<std::int64_t>(&sid_val->storage());
                REQUIRE(sid_int != nullptr);
                REQUIRE(*sid_int == 42);
            }
        }
    }
}

// Spec: each device entry's keys field MUST carry the device identity keys so
// remote servers can build Olm sessions with the correct curve25519 key.
// A missing or wrong key causes OlmError::MissingCiphertext on the recipient.
// ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixfederationv1userdevicescircumflex
SCENARIO("Federation user-devices response device entry carries the curve25519 identity key",
         "[federation][keys][devices]")
{
    GIVEN("a store with a device that has a curve25519 identity key")
    {
        auto store = merovingian::database::PersistentStore{};
        store.device_keys.push_back(
            {"@alice:example.org", "ALICE1",
             R"({"algorithms":["m.olm.v1.curve25519-aes-sha2"],"device_id":"ALICE1","keys":{"curve25519:ALICE1":"AAAAAA","ed25519:ALICE1":"BBBBBB"},"user_id":"@alice:example.org","signatures":{}})"});

        WHEN("the user's devices are queried")
        {
            auto const body = merovingian::federation::build_user_devices_response(store, "@alice:example.org");

            THEN("the device entry's keys field contains the curve25519 identity key")
            {
                REQUIRE_FALSE(body.empty());
                auto const parsed = merovingian::canonicaljson::parse_lossless(body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* devs_val = json_get(*root, std::string{"devices"});
                auto const* devs_arr = std::get_if<merovingian::canonicaljson::Array>(&devs_val->storage());
                REQUIRE(devs_arr->size() == 1U);

                auto const* device_obj =
                    std::get_if<merovingian::canonicaljson::Object>(&(*devs_arr)[0].storage());
                REQUIRE(device_obj != nullptr);

                // Spec MUST: keys field contains the full device keys object.
                auto const* keys_val = json_get(*device_obj, std::string{"keys"});
                REQUIRE(keys_val != nullptr);
                auto const* keys_obj = std::get_if<merovingian::canonicaljson::Object>(&keys_val->storage());
                REQUIRE(keys_obj != nullptr);

                // Spec MUST: device keys object has a nested keys map with the curve25519 key.
                auto const* inner_keys_val = json_get(*keys_obj, std::string{"keys"});
                REQUIRE(inner_keys_val != nullptr);
                auto const* inner_keys_obj =
                    std::get_if<merovingian::canonicaljson::Object>(&inner_keys_val->storage());
                REQUIRE(inner_keys_obj != nullptr);
                auto const* curve_val = json_get(*inner_keys_obj, std::string{"curve25519:ALICE1"});
                REQUIRE(curve_val != nullptr);
                auto const* curve_str = std::get_if<std::string>(&curve_val->storage());
                REQUIRE(curve_str != nullptr);
                REQUIRE(*curve_str == "AAAAAA");
            }
        }
    }
}
