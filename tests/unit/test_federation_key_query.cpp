// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX FEDERATION KEY QUERY CONFORMANCE TESTS                   |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                 |
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

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

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
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1userkeysquery
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
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1userkeyesclaim
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
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1userdevicescircumflex
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
// ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1userdevicescircumflex
SCENARIO("Federation user-devices response reflects the store sync stream counter", "[federation][keys][devices]")
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
// ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1userdevicescircumflex
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

                auto const* device_obj = std::get_if<merovingian::canonicaljson::Object>(&(*devs_arr)[0].storage());
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

namespace
{

namespace cj = merovingian::canonicaljson;
namespace fed = merovingian::federation;

[[nodiscard]] auto parse_root(std::string const& body) -> cj::Object
{
    auto parsed = cj::parse_lossless(body);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const* root = std::get_if<cj::Object>(&parsed.value.storage());
    REQUIRE(root != nullptr);
    return *root;
}

[[nodiscard]] auto object_at(cj::Object const& object, std::string const& key) -> cj::Object const*
{
    auto const* value = json_get(object, key);
    return value == nullptr ? nullptr : std::get_if<cj::Object>(&value->storage());
}

[[nodiscard]] auto array_at(cj::Object const& object, std::string const& key) -> cj::Array const*
{
    auto const* value = json_get(object, key);
    return value == nullptr ? nullptr : std::get_if<cj::Array>(&value->storage());
}

[[nodiscard]] auto string_at(cj::Object const& object, std::string const& key) -> std::string const*
{
    auto const* value = json_get(object, key);
    return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
}

[[nodiscard]] auto int_at(cj::Object const& object, std::string const& key) -> std::int64_t const*
{
    auto const* value = json_get(object, key);
    return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
}

// signatures[signer][key_id] of a key object, or nullptr when any level is missing.
[[nodiscard]] auto signature_of(cj::Object const& key_object, std::string const& signer, std::string const& key_id)
    -> std::string const*
{
    auto const* signatures = object_at(key_object, "signatures");
    auto const* by_signer = signatures == nullptr ? nullptr : object_at(*signatures, signer);
    auto const* value = by_signer == nullptr ? nullptr : json_get(*by_signer, key_id);
    return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
}

// Alice (local) has cross-signed her device and her device has signed her
// master key, both uploaded through /keys/signatures/upload under the spec
// key IDs (device ID; bare base64 master public key). Carol (local) has also
// uploaded a user-signing signature over alice's master key.
[[nodiscard]] auto store_with_cross_signed_alice() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    store.device_keys.push_back(
        {"@alice:example.org", "ADEVICE",
         R"({"algorithms":["m.olm.v1.curve25519-aes-sha2"],"device_id":"ADEVICE","keys":{"curve25519:ADEVICE":"curve","ed25519:ADEVICE":"edkey"},"signatures":{"@alice:example.org":{"ed25519:ADEVICE":"self-sig"}},"user_id":"@alice:example.org"})"});
    store.cross_signing_keys.push_back(
        {"@alice:example.org", "master",
         R"({"keys":{"ed25519:ALICEMASTER":"ALICEMASTER"},"usage":["master"],"user_id":"@alice:example.org"})"});
    store.cross_signing_keys.push_back(
        {"@alice:example.org", "self_signing",
         R"({"keys":{"ed25519:ALICESSK":"ALICESSK"},"signatures":{"@alice:example.org":{"ed25519:ALICEMASTER":"msk-sig"}},"usage":["self_signing"],"user_id":"@alice:example.org"})"});
    store.cross_signing_keys.push_back(
        {"@alice:example.org", "user_signing",
         R"({"keys":{"ed25519:ALICEUSK":"ALICEUSK"},"usage":["user_signing"],"user_id":"@alice:example.org"})"});
    store.key_signatures.push_back(
        {"@alice:example.org", "@alice:example.org", "ADEVICE",
         R"({"device_id":"ADEVICE","signatures":{"@alice:example.org":{"ed25519:ALICESSK":"ssk-sig"}},"user_id":"@alice:example.org"})"});
    store.key_signatures.push_back(
        {"@alice:example.org", "@alice:example.org", "ALICEMASTER",
         R"({"keys":{"ed25519:ALICEMASTER":"ALICEMASTER"},"signatures":{"@alice:example.org":{"ed25519:ADEVICE":"device-sig"}},"usage":["master"],"user_id":"@alice:example.org"})"});
    store.key_signatures.push_back(
        {"@carol:example.org", "@alice:example.org", "ALICEMASTER",
         R"({"keys":{"ed25519:ALICEMASTER":"ALICEMASTER"},"signatures":{"@carol:example.org":{"ed25519:CAROLUSK":"carol-sig"}},"usage":["master"],"user_id":"@alice:example.org"})"});
    return store;
}

} // namespace

// --- Signatures in keys served over federation -------------------------------
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1userkeysquery
//
// master_keys: "the information returned will be the same as uploaded via
// /keys/device_signing/upload, along with the signatures uploaded via
// /keys/signatures/upload that the user is allowed to see". A remote user can
// only tell that a device is trusted by its owner if the owner's self-signing
// signature over that device reaches them.
SCENARIO("Federation device-key query publishes the owner's cross-signing signatures",
         "[federation][keys][query][signatures][regression]")
{
    GIVEN("a local user who has cross-signed their device")
    {
        auto const store = store_with_cross_signed_alice();

        WHEN("a remote server queries the user's keys")
        {
            auto const root = parse_root(
                fed::build_device_keys_query_response(store, R"({"device_keys":{"@alice:example.org":[]}})"));

            THEN("the device carries the owner's self-signing signature as well as its own")
            {
                auto const* device_keys = object_at(root, "device_keys");
                REQUIRE(device_keys != nullptr);
                auto const* alice_devices = object_at(*device_keys, "@alice:example.org");
                REQUIRE(alice_devices != nullptr);
                auto const* device = object_at(*alice_devices, "ADEVICE");
                REQUIRE(device != nullptr);
                auto const* ssk_sig = signature_of(*device, "@alice:example.org", "ed25519:ALICESSK");
                REQUIRE(ssk_sig != nullptr);
                REQUIRE(*ssk_sig == "ssk-sig");
                REQUIRE(signature_of(*device, "@alice:example.org", "ed25519:ADEVICE") != nullptr);
            }

            AND_THEN("the master key carries the owner's device signature but not another user's")
            {
                auto const* master_keys = object_at(root, "master_keys");
                REQUIRE(master_keys != nullptr);
                auto const* master = object_at(*master_keys, "@alice:example.org");
                REQUIRE(master != nullptr);
                auto const* device_sig = signature_of(*master, "@alice:example.org", "ed25519:ADEVICE");
                REQUIRE(device_sig != nullptr);
                REQUIRE(*device_sig == "device-sig");
                // A signature carol uploaded is only for carol to see.
                REQUIRE(signature_of(*master, "@carol:example.org", "ed25519:CAROLUSK") == nullptr);
            }

            AND_THEN("the self-signing key is published and the user-signing key is not")
            {
                auto const* self_signing_keys = object_at(root, "self_signing_keys");
                REQUIRE(self_signing_keys != nullptr);
                REQUIRE(object_at(*self_signing_keys, "@alice:example.org") != nullptr);
                // Spec: the user-signing key is only ever returned to its owner.
                REQUIRE(json_get(root, "user_signing_keys") == nullptr);
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1userdevicescircumflex
//
// A remote server that resyncs a user's device list through /user/devices
// caches these keys, so they must carry the same signatures /user/keys/query does.
SCENARIO("Federation user-devices response publishes the owner's cross-signing signatures",
         "[federation][keys][devices][signatures][regression]")
{
    GIVEN("a local user who has cross-signed their device")
    {
        auto const store = store_with_cross_signed_alice();

        WHEN("a remote server fetches the user's device list")
        {
            auto const root = parse_root(fed::build_user_devices_response(store, "@alice:example.org"));

            THEN("the device keys carry the owner's self-signing signature")
            {
                auto const* devices = array_at(root, "devices");
                REQUIRE(devices != nullptr);
                REQUIRE(devices->size() == 1U);
                auto const* device = std::get_if<cj::Object>(&devices->front().storage());
                REQUIRE(device != nullptr);
                auto const* keys = object_at(*device, "keys");
                REQUIRE(keys != nullptr);
                REQUIRE(signature_of(*keys, "@alice:example.org", "ed25519:ALICESSK") != nullptr);
            }

            AND_THEN("the master key carries the owner's device signature")
            {
                auto const* master = object_at(root, "master_key");
                REQUIRE(master != nullptr);
                REQUIRE(signature_of(*master, "@alice:example.org", "ed25519:ADEVICE") != nullptr);
                REQUIRE(signature_of(*master, "@carol:example.org", "ed25519:CAROLUSK") == nullptr);
            }
        }
    }
}

// --- Remote /user/keys/query responses ----------------------------------------
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1userkeysquery
//
// The response carries device_keys, master_keys and self_signing_keys. A
// client needs the remote user's master and self-signing keys to tell whether
// a remote device is signed by its owner. The remote server can only speak
// for its own users, and only for the users it was asked about ("Requested
// users must be local to the receiving homeserver").
SCENARIO("A remote key-query response yields the remote user's device and cross-signing keys",
         "[federation][keys][query][remote][regression]")
{
    GIVEN("a well-formed response from bob's server")
    {
        auto const response = std::string{
            R"({"device_keys":{"@bob:remote.example.org":{"BDEV":{"algorithms":["m.megolm.v1.aes-sha2"],"device_id":"BDEV","keys":{"ed25519:BDEV":"bdev"},"signatures":{"@bob:remote.example.org":{"ed25519:BOBSSK":"ssk-sig"}},"user_id":"@bob:remote.example.org"}}},)"
            R"("master_keys":{"@bob:remote.example.org":{"keys":{"ed25519:BOBMASTER":"BOBMASTER"},"usage":["master"],"user_id":"@bob:remote.example.org"}},)"
            R"("self_signing_keys":{"@bob:remote.example.org":{"keys":{"ed25519:BOBSSK":"BOBSSK"},"signatures":{"@bob:remote.example.org":{"ed25519:BOBMASTER":"msk-sig"}},"usage":["self_signing"],"user_id":"@bob:remote.example.org"}}})"};
        auto const requested = std::vector<std::string>{"@bob:remote.example.org"};

        WHEN("it is accepted")
        {
            auto const accepted = fed::accept_remote_key_query_response("remote.example.org", response, requested);

            THEN("the device, master and self-signing keys are all kept")
            {
                REQUIRE(accepted.has_value());
                auto const* devices = object_at(accepted->device_keys, "@bob:remote.example.org");
                REQUIRE(devices != nullptr);
                REQUIRE(object_at(*devices, "BDEV") != nullptr);
                REQUIRE(object_at(accepted->master_keys, "@bob:remote.example.org") != nullptr);
                auto const* self_signing = object_at(accepted->self_signing_keys, "@bob:remote.example.org");
                REQUIRE(self_signing != nullptr);
                REQUIRE(signature_of(*self_signing, "@bob:remote.example.org", "ed25519:BOBMASTER") != nullptr);
            }
        }
    }
}

SCENARIO("A remote key-query response cannot inject keys for users it was not asked about",
         "[federation][keys][query][remote][security]")
{
    GIVEN("a response from evil.example.org that also answers for a user on another server")
    {
        auto const response = std::string{
            R"({"device_keys":{"@alice:good.example.org":{"EVIL":{"device_id":"EVIL","keys":{"ed25519:EVIL":"x"},"user_id":"@alice:good.example.org"}},)"
            R"("@eve:evil.example.org":{"EDEV":{"device_id":"EDEV","keys":{"ed25519:EDEV":"x"},"user_id":"@eve:evil.example.org"}}},)"
            R"("master_keys":{"@alice:good.example.org":{"keys":{"ed25519:FAKE":"FAKE"},"usage":["master"],"user_id":"@alice:good.example.org"},)"
            R"("@eve:evil.example.org":{"keys":{"ed25519:EVE":"EVE"},"usage":["master"],"user_id":"@eve:evil.example.org"}},)"
            R"("self_signing_keys":{"@alice:good.example.org":{"keys":{"ed25519:FAKESSK":"FAKESSK"},"usage":["self_signing"],"user_id":"@alice:good.example.org"}}})"};
        auto const requested = std::vector<std::string>{"@eve:evil.example.org"};

        WHEN("it is accepted")
        {
            auto const accepted = fed::accept_remote_key_query_response("evil.example.org", response, requested);

            THEN("only the requested user's keys survive")
            {
                REQUIRE(accepted.has_value());
                REQUIRE(object_at(accepted->device_keys, "@alice:good.example.org") == nullptr);
                REQUIRE(object_at(accepted->master_keys, "@alice:good.example.org") == nullptr);
                REQUIRE(object_at(accepted->self_signing_keys, "@alice:good.example.org") == nullptr);
                REQUIRE(object_at(accepted->device_keys, "@eve:evil.example.org") != nullptr);
                REQUIRE(object_at(accepted->master_keys, "@eve:evil.example.org") != nullptr);
            }
        }
    }
}

SCENARIO("A remote key-query response drops keys that do not describe the user they are filed under",
         "[federation][keys][query][remote][security]")
{
    GIVEN("a response whose entries for bob name another user, another device, or the wrong usage")
    {
        auto const response = std::string{
            R"({"device_keys":{"@bob:remote.example.org":{)"
            R"("GOOD":{"device_id":"GOOD","keys":{"ed25519:GOOD":"x"},"user_id":"@bob:remote.example.org"},)"
            R"("WRONGID":{"device_id":"OTHER","keys":{"ed25519:OTHER":"x"},"user_id":"@bob:remote.example.org"},)"
            R"("WRONGUSER":{"device_id":"WRONGUSER","keys":{"ed25519:WRONGUSER":"x"},"user_id":"@carl:remote.example.org"}}},)"
            R"("master_keys":{"@bob:remote.example.org":{"keys":{"ed25519:M":"M"},"usage":["master"],"user_id":"@carl:remote.example.org"}},)"
            R"("self_signing_keys":{"@bob:remote.example.org":{"keys":{"ed25519:S":"S"},"usage":["user_signing"],"user_id":"@bob:remote.example.org"}}})"};
        auto const requested = std::vector<std::string>{"@bob:remote.example.org"};

        WHEN("it is accepted")
        {
            auto const accepted = fed::accept_remote_key_query_response("remote.example.org", response, requested);

            THEN("only the self-consistent device is kept")
            {
                REQUIRE(accepted.has_value());
                auto const* devices = object_at(accepted->device_keys, "@bob:remote.example.org");
                REQUIRE(devices != nullptr);
                REQUIRE(object_at(*devices, "GOOD") != nullptr);
                REQUIRE(object_at(*devices, "WRONGID") == nullptr);
                REQUIRE(object_at(*devices, "WRONGUSER") == nullptr);
                REQUIRE(object_at(accepted->master_keys, "@bob:remote.example.org") == nullptr);
                REQUIRE(object_at(accepted->self_signing_keys, "@bob:remote.example.org") == nullptr);
            }
        }
    }

    GIVEN("a response body that is not a JSON object")
    {
        auto const requested = std::vector<std::string>{"@bob:remote.example.org"};

        WHEN("it is accepted")
        {
            auto const not_json = fed::accept_remote_key_query_response("remote.example.org", "not json", requested);
            auto const array = fed::accept_remote_key_query_response("remote.example.org", "[]", requested);

            THEN("nothing is accepted")
            {
                REQUIRE_FALSE(not_json.has_value());
                REQUIRE_FALSE(array.has_value());
            }
        }
    }
}

// --- m.signing_key_update -----------------------------------------------------
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#msigning_key_update
//
// "An EDU that lets servers push details to each other when one of their
// users updates their cross-signing keys." Content: user_id (required),
// master_key, self_signing_key. The user-signing key is private and is never sent.
SCENARIO("The m.signing_key_update EDU carries the user's public cross-signing keys",
         "[federation][keys][edu][signing-key-update]")
{
    GIVEN("a local user with master, self-signing and user-signing keys")
    {
        auto const store = store_with_cross_signed_alice();

        WHEN("the EDU content is built")
        {
            auto const content = fed::build_signing_key_update_content(store, "@alice:example.org");

            THEN("it names the user and carries the master and self-signing keys only")
            {
                REQUIRE(content.has_value());
                auto const root = parse_root(*content);
                auto const* user_id = string_at(root, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(*user_id == "@alice:example.org");
                auto const* master = object_at(root, "master_key");
                REQUIRE(master != nullptr);
                // The owner's own signatures travel with the key.
                REQUIRE(signature_of(*master, "@alice:example.org", "ed25519:ADEVICE") != nullptr);
                REQUIRE(signature_of(*master, "@carol:example.org", "ed25519:CAROLUSK") == nullptr);
                REQUIRE(object_at(root, "self_signing_key") != nullptr);
                REQUIRE(json_get(root, "user_signing_key") == nullptr);
            }
        }
    }

    GIVEN("a user with no cross-signing keys")
    {
        auto const store = merovingian::database::PersistentStore{};

        WHEN("the EDU content is built")
        {
            auto const content = fed::build_signing_key_update_content(store, "@nobody:example.org");

            THEN("there is nothing to send")
            {
                REQUIRE_FALSE(content.has_value());
            }
        }
    }
}

// --- m.device_list_update -----------------------------------------------------
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#mdevice_list_update
//
// A receiving server may apply the EDU's `keys` straight to its cache
// without refetching, so the keys must be the device keys as published —
// with the owner's self-signing signature — or the remote side caches the
// device as not cross-signed.
SCENARIO("The m.device_list_update EDU carries the device keys with the owner's signatures",
         "[federation][keys][edu][device-list-update][regression]")
{
    GIVEN("a local user who has cross-signed their device")
    {
        auto const store = store_with_cross_signed_alice();

        WHEN("the EDU content is built for that device")
        {
            auto const content = fed::build_device_list_update_content(store, "@alice:example.org", "ADEVICE", 7);

            THEN("it identifies the device and its keys carry the self-signing signature")
            {
                REQUIRE(content.has_value());
                auto const root = parse_root(*content);
                auto const* user_id = string_at(root, "user_id");
                REQUIRE(user_id != nullptr);
                REQUIRE(*user_id == "@alice:example.org");
                auto const* device_id = string_at(root, "device_id");
                REQUIRE(device_id != nullptr);
                REQUIRE(*device_id == "ADEVICE");
                auto const* stream_id = int_at(root, "stream_id");
                REQUIRE(stream_id != nullptr);
                REQUIRE(*stream_id == 7);
                REQUIRE(array_at(root, "prev_id") != nullptr);
                auto const* keys = object_at(root, "keys");
                REQUIRE(keys != nullptr);
                REQUIRE(signature_of(*keys, "@alice:example.org", "ed25519:ALICESSK") != nullptr);
            }
        }

        WHEN("the EDU content is built for a device with no published keys")
        {
            auto const content = fed::build_device_list_update_content(store, "@alice:example.org", "NOKEYS", 7);

            THEN("it still identifies the device but carries no keys")
            {
                REQUIRE(content.has_value());
                auto const root = parse_root(*content);
                REQUIRE(json_get(root, "device_id") != nullptr);
                REQUIRE(json_get(root, "keys") == nullptr);
            }
        }
    }
}
