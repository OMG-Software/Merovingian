// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Signature visibility for published E2EE keys.
//
// Spec: Matrix Client-Server API v1.19, POST /_matrix/client/v3/keys/query
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3keysquery
// Spec: Matrix Server-Server API v1.19, POST /_matrix/federation/v1/user/keys/query
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#post_matrixfederationv1userkeysquery
//
// Keys are returned "along with the signatures uploaded via
// /keys/signatures/upload that the requesting user is allowed to see". The
// upload is keyed by device ID for device keys and by the unpadded base64
// public key for cross-signing keys (see the /keys/signatures/upload request
// example). See ADR-0060 for the visibility rule.

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/key_signatures.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace
{

namespace cj = merovingian::canonicaljson;
namespace fed = merovingian::federation;

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:remote.example.org"};
constexpr auto carol = std::string_view{"@carol:example.org"};

[[nodiscard]] auto parse(std::string_view json) -> cj::Object
{
    auto parsed = cj::parse_lossless(json);
    REQUIRE(parsed.error == cj::ParseError::none);
    auto const* object = std::get_if<cj::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

[[nodiscard]] auto member(cj::Object const& object, std::string_view key) -> cj::Value const*
{
    for (auto const& entry : object)
    {
        if (entry.key == key)
        {
            return entry.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto member_object(cj::Object const& object, std::string_view key) -> cj::Object const*
{
    auto const* value = member(object, key);
    return value == nullptr ? nullptr : std::get_if<cj::Object>(&value->storage());
}

// signatures[signer][key_id], or nullptr when any level is missing.
[[nodiscard]] auto signature(cj::Object const& key_object, std::string_view signer, std::string_view key_id)
    -> std::string const*
{
    auto const* signatures = member_object(key_object, "signatures");
    if (signatures == nullptr)
    {
        return nullptr;
    }
    auto const* by_signer = member_object(*signatures, signer);
    if (by_signer == nullptr)
    {
        return nullptr;
    }
    auto const* value = member(*by_signer, key_id);
    return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
}

// Alice's published keys: one device and a master key whose public key is
// "ALICEMASTER", so the master key's upload key ID is "ALICEMASTER".
[[nodiscard]] auto store_with_alice_keys() -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    store.device_keys.push_back(
        {std::string{alice}, "ADEVICE",
         R"({"device_id":"ADEVICE","keys":{"ed25519:ADEVICE":"adev"},"signatures":{"@alice:example.org":{"ed25519:ADEVICE":"self-sig"}},"user_id":"@alice:example.org"})"});
    store.cross_signing_keys.push_back(
        {std::string{alice}, "master",
         R"({"keys":{"ed25519:ALICEMASTER":"ALICEMASTER"},"usage":["master"],"user_id":"@alice:example.org"})"});
    return store;
}

} // namespace

SCENARIO("A cross-signing key is addressed by its unpadded base64 public key", "[federation][keys][signatures]")
{
    GIVEN("a cross-signing key object with one ed25519 key")
    {
        auto const key = parse(R"({"keys":{"ed25519:base64+master+public+key":"base64+master+public+key"}})");

        WHEN("its upload key ID is derived")
        {
            auto const key_id = fed::cross_signing_key_id(key);

            THEN("it is the key name without the algorithm prefix, as /keys/signatures/upload addresses it")
            {
                REQUIRE(key_id.has_value());
                REQUIRE(*key_id == "base64+master+public+key");
            }
        }
    }

    GIVEN("key objects that do not hold exactly one algorithm-prefixed key")
    {
        auto const no_keys = parse(R"({"usage":["master"]})");
        auto const two_keys = parse(R"({"keys":{"ed25519:A":"A","ed25519:B":"B"}})");
        auto const no_prefix = parse(R"({"keys":{"A":"A"}})");
        auto const empty_id = parse(R"({"keys":{"ed25519:":"A"}})");

        WHEN("their upload key IDs are derived")
        {
            THEN("none has one")
            {
                REQUIRE_FALSE(fed::cross_signing_key_id(no_keys).has_value());
                REQUIRE_FALSE(fed::cross_signing_key_id(two_keys).has_value());
                REQUIRE_FALSE(fed::cross_signing_key_id(no_prefix).has_value());
                REQUIRE_FALSE(fed::cross_signing_key_id(empty_id).has_value());
            }
        }
    }
}

SCENARIO("A device's owner-uploaded self-signing signature is published to everyone", "[federation][keys][signatures]")
{
    GIVEN("alice has signed her device with her self-signing key")
    {
        auto store = store_with_alice_keys();
        store.key_signatures.push_back(
            {std::string{alice}, std::string{alice}, "ADEVICE",
             R"({"device_id":"ADEVICE","signatures":{"@alice:example.org":{"ed25519:ALICESSK":"ssk-sig"}},"user_id":"@alice:example.org"})"});

        WHEN("the device is published to a remote server and to another local user")
        {
            auto const to_server = fed::published_device_keys(store, store.device_keys.front(), std::nullopt);
            auto const to_carol = fed::published_device_keys(store, store.device_keys.front(), carol);

            THEN("both see the self-signing signature alongside the device's own signature")
            {
                REQUIRE(to_server.has_value());
                REQUIRE(to_carol.has_value());
                for (auto const& published : {*to_server, *to_carol})
                {
                    auto const* ssk_sig = signature(published, alice, "ed25519:ALICESSK");
                    REQUIRE(ssk_sig != nullptr);
                    REQUIRE(*ssk_sig == "ssk-sig");
                    auto const* self_sig = signature(published, alice, "ed25519:ADEVICE");
                    REQUIRE(self_sig != nullptr);
                    REQUIRE(*self_sig == "self-sig");
                }
            }
        }
    }
}

SCENARIO("A signature on a cross-signing key is found under the key's spec upload key ID",
         "[federation][keys][signatures][regression]")
{
    GIVEN("alice's device has signed her master key, uploaded under the bare base64 key ID")
    {
        auto store = store_with_alice_keys();
        store.key_signatures.push_back(
            {std::string{alice}, std::string{alice}, "ALICEMASTER",
             R"({"keys":{"ed25519:ALICEMASTER":"ALICEMASTER"},"signatures":{"@alice:example.org":{"ed25519:ADEVICE":"device-sig"}},"usage":["master"],"user_id":"@alice:example.org"})"});

        WHEN("the master key is published")
        {
            auto const published = fed::published_cross_signing_key(store, alice, "master", std::nullopt);

            THEN("the device's signature is merged into it")
            {
                REQUIRE(published.has_value());
                auto const* device_sig = signature(*published, alice, "ed25519:ADEVICE");
                REQUIRE(device_sig != nullptr);
                REQUIRE(*device_sig == "device-sig");
            }
        }
    }
}

SCENARIO("A user-signing signature over another user's master key is visible only to its signer",
         "[federation][keys][signatures][privacy]")
{
    GIVEN("alice has verified bob and uploaded her user-signing signature over bob's master key")
    {
        auto store = merovingian::database::PersistentStore{};
        store.key_signatures.push_back(
            {std::string{alice}, std::string{bob}, "BOBMASTER",
             R"({"keys":{"ed25519:BOBMASTER":"BOBMASTER"},"signatures":{"@alice:example.org":{"ed25519:ALICEUSK":"usk-sig"}},"usage":["master"],"user_id":"@bob:remote.example.org"})"});
        auto const bobs_master = std::string{
            R"({"keys":{"ed25519:BOBMASTER":"BOBMASTER"},"signatures":{"@bob:remote.example.org":{"ed25519:BOBDEV":"bob-sig"}},"usage":["master"],"user_id":"@bob:remote.example.org"})"};

        WHEN("bob's master key is published to alice")
        {
            auto key = parse(bobs_master);
            fed::merge_visible_key_signatures(key, store, bob, "BOBMASTER", alice);

            THEN("alice sees her own signature and bob's existing signature survives")
            {
                auto const* usk_sig = signature(key, alice, "ed25519:ALICEUSK");
                REQUIRE(usk_sig != nullptr);
                REQUIRE(*usk_sig == "usk-sig");
                REQUIRE(signature(key, bob, "ed25519:BOBDEV") != nullptr);
            }
        }

        WHEN("bob's master key is published to carol")
        {
            auto key = parse(bobs_master);
            fed::merge_visible_key_signatures(key, store, bob, "BOBMASTER", carol);

            THEN("carol does not learn that alice verified bob")
            {
                REQUIRE(signature(key, alice, "ed25519:ALICEUSK") == nullptr);
                REQUIRE(signature(key, bob, "ed25519:BOBDEV") != nullptr);
            }
        }

        WHEN("bob's master key is published to a remote server")
        {
            auto key = parse(bobs_master);
            fed::merge_visible_key_signatures(key, store, bob, "BOBMASTER", std::nullopt);

            THEN("the server does not see alice's signature either")
            {
                REQUIRE(signature(key, alice, "ed25519:ALICEUSK") == nullptr);
            }
        }
    }
}

SCENARIO("An uploader cannot publish a signature under another user's name", "[federation][keys][signatures][security]")
{
    GIVEN("carol uploaded a 'signature' on alice's device that claims to be from alice")
    {
        auto store = store_with_alice_keys();
        store.key_signatures.push_back(
            {std::string{carol}, std::string{alice}, "ADEVICE",
             R"({"device_id":"ADEVICE","signatures":{"@alice:example.org":{"ed25519:FORGED":"forged"},"@carol:example.org":{"ed25519:CAROLUSK":"carol-sig"}},"user_id":"@alice:example.org"})"});

        WHEN("the device is published to carol herself")
        {
            auto const published = fed::published_device_keys(store, store.device_keys.front(), carol);

            THEN("only carol's own signer entry is merged, never the one naming alice")
            {
                REQUIRE(published.has_value());
                REQUIRE(signature(*published, alice, "ed25519:FORGED") == nullptr);
                REQUIRE(signature(*published, carol, "ed25519:CAROLUSK") != nullptr);
            }
        }

        WHEN("the device is published to a remote server")
        {
            auto const published = fed::published_device_keys(store, store.device_keys.front(), std::nullopt);

            THEN("neither of carol's entries is visible")
            {
                REQUIRE(published.has_value());
                REQUIRE(signature(*published, alice, "ed25519:FORGED") == nullptr);
                REQUIRE(signature(*published, carol, "ed25519:CAROLUSK") == nullptr);
            }
        }
    }
}

SCENARIO("A cross-signing key the user never published is absent", "[federation][keys][signatures]")
{
    GIVEN("alice has a master key but no self-signing key")
    {
        auto const store = store_with_alice_keys();

        WHEN("each key type is looked up")
        {
            auto const master = fed::published_cross_signing_key(store, alice, "master", std::nullopt);
            auto const self_signing = fed::published_cross_signing_key(store, alice, "self_signing", std::nullopt);

            THEN("only the master key is returned")
            {
                REQUIRE(master.has_value());
                REQUIRE_FALSE(self_signing.has_value());
            }
        }
    }
}
