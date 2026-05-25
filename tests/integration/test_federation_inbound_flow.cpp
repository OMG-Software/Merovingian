// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/vertical_slice.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include "federation_signing_test_support.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <sodium.h>

namespace
{

[[nodiscard]] auto federation_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.federation.enabled = true;
    security.federation.default_policy = "allow";
    security.federation.max_transaction_size = "1MiB";
    security.federation.remote_timeout = "30s";
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto remote_for(std::string const& origin, std::string const& key_id, std::string const& key_seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = origin;
    remote.signing_key = {origin, key_id, 2000U, merovingian::federation::test::keypair_from_seed(key_seed).public_key};
    remote.discovery.server_name = origin;
    remote.discovery.well_known_host = origin;
    remote.discovery.resolved_host = origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

// The default ServerConfig server name produced by federation_config().
auto constexpr local_server_name = std::string_view{"example.org"};

// Builds the pipe-delimited federation auth token used by the router's
// test-fixture fallback path:
// origin|key_id|signature|destination|now_ts|canonical_flag.
[[nodiscard]] auto federation_authorization(std::string const& origin, std::string const& key_id,
                                            std::string const& key_seed, std::string const& method,
                                            std::string const& target, std::string const& body,
                                            std::string const& canonical_flag = "canonical") -> std::string
{
    auto const destination = std::string{local_server_name};
    auto const signature = merovingian::federation::make_federation_signature(
        origin, destination, method, target, body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return origin + '|' + key_id + '|' + signature + '|' + destination + "|1000|" + canonical_flag;
}

[[nodiscard]] auto sodium_is_ready() noexcept -> bool
{
    static auto const ready = sodium_init() >= 0;
    return ready;
}

auto derive_test_keypair(std::string_view key_material,
                         std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>& public_key,
                         std::array<unsigned char, crypto_sign_SECRETKEYBYTES>& secret_key) noexcept -> bool
{
    if (!sodium_is_ready())
    {
        return false;
    }
    auto seed = std::array<unsigned char, crypto_sign_SEEDBYTES>{};
    if (crypto_generichash(seed.data(), seed.size(), reinterpret_cast<unsigned char const*>(key_material.data()),
                           key_material.size(), nullptr, 0U) != 0)
    {
        return false;
    }
    return crypto_sign_seed_keypair(public_key.data(), secret_key.data(), seed.data()) == 0;
}

class IntegrationTestSigningStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit IntegrationTestSigningStore(merovingian::crypto::SigningKeyRecord key)
        : key_{std::move(key)}
    {
    }

    [[nodiscard]] auto active_key_for_server(std::string_view server_name)
        -> merovingian::crypto::SigningKeyLookupResult override
    {
        if (server_name != key_.server_name)
        {
            return {{}, "signing key not found"};
        }
        return {key_, {}};
    }

private:
    merovingian::crypto::SigningKeyRecord key_{};
};

class IntegrationTestEd25519Provider final : public merovingian::crypto::Ed25519Provider
{
public:
    explicit IntegrationTestEd25519Provider(std::string key_material)
        : key_material_{std::move(key_material)}
    {
    }

    [[nodiscard]] auto sign(merovingian::crypto::Ed25519SecretKeyHandle const&, std::string_view message)
        -> merovingian::crypto::SignatureResult override
    {
        auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
        auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
        if (!derive_test_keypair(key_material_, public_key, secret_key))
        {
            return {{}, "unable to derive signing key"};
        }
        auto signature = std::string(crypto_sign_BYTES, '\0');
        if (crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                 reinterpret_cast<unsigned char const*>(message.data()), message.size(),
                                 secret_key.data()) != 0)
        {
            return {{}, "signing failed"};
        }
        return {merovingian::crypto::Ed25519Signature{std::move(signature)}, {}};
    }

    [[nodiscard]] auto verify(merovingian::crypto::Ed25519PublicKey const&, std::string_view,
                              merovingian::crypto::Ed25519Signature const&)
        -> merovingian::crypto::VerificationResult override
    {
        return {false, "test provider does not verify"};
    }

private:
    std::string key_material_{};
};

[[nodiscard]] auto signed_json_pdu(std::string const& origin, std::string const& key_id, std::string const& token)
    -> std::string
{
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(derive_test_keypair(token, public_key, secret_key));
    auto const event_json =
        "{\"auth_events\":[],\"content\":{\"body\":\"hi\",\"msgtype\":\"m.text\"},\"depth\":1,\"hashes\":{\"sha256\":"
        "\"hash\"},\"origin_server_ts\":1,\"prev_events\":[],\"room_id\":\"!room:example.org\",\"sender\":\"@alice:" +
        origin + "\",\"type\":\"m.room.message\"}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    REQUIRE(policy != nullptr);
    auto store = IntegrationTestSigningStore{
        merovingian::crypto::SigningKeyRecord{
                                              origin, key_id,
                                              merovingian::crypto::Ed25519PublicKey{
                std::string{reinterpret_cast<char const*>(public_key.data()), public_key.size()}},
                                              true, }
    };
    auto provider = IntegrationTestEd25519Provider{token};
    auto signed_event = merovingian::events::sign_event_for_server(parsed.value, *policy, store, provider, origin);
    REQUIRE(signed_event.error.empty());
    return signed_event.event_json;
}

[[nodiscard]] auto object_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

[[nodiscard]] auto string_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::string const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
}

[[nodiscard]] auto integer_member(merovingian::canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::int64_t const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
}

[[nodiscard]] auto object_member_as_object(merovingian::canonicaljson::Object const& object,
                                           std::string_view key) noexcept -> merovingian::canonicaljson::Object const*
{
    auto const* value = object_member(object, key);
    return value == nullptr ? nullptr : std::get_if<merovingian::canonicaljson::Object>(&value->storage());
}

[[nodiscard]] auto clone_without_signatures(merovingian::canonicaljson::Object const& object)
    -> merovingian::canonicaljson::Object
{
    auto clone = merovingian::canonicaljson::Object{};
    for (auto const& member : object)
    {
        if (member.key != "signatures")
        {
            clone.push_back(merovingian::canonicaljson::make_member(member.key, *member.value));
        }
    }
    return clone;
}

} // namespace

SCENARIO("Homeserver publishes its persisted self-signed federation key without request authentication",
         "[integration][federation][keys]")
{
    GIVEN("a started runtime with no prior event signing")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a remote homeserver fetches GET /_matrix/key/v2/server without Authorization")
        {
            auto const response =
                merovingian::homeserver::handle_local_http_request(runtime, {"GET", "/_matrix/key/v2/server", {}, {}});

            THEN("the response publishes the persisted Ed25519 verify key and a valid self-signature")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(object != nullptr);

                auto const* server_name = string_member(*object, "server_name");
                auto const* valid_until_ts = integer_member(*object, "valid_until_ts");
                auto const* verify_keys = object_member_as_object(*object, "verify_keys");
                auto const* signatures = object_member_as_object(*object, "signatures");
                REQUIRE(server_name != nullptr);
                REQUIRE(*server_name == "example.org");
                REQUIRE(valid_until_ts != nullptr);
                REQUIRE(*valid_until_ts > 0);
                REQUIRE(verify_keys != nullptr);
                REQUIRE(signatures != nullptr);

                auto const* key_object = object_member_as_object(*verify_keys, "ed25519:auto");
                REQUIRE(key_object != nullptr);
                auto const* public_key = string_member(*key_object, "key");
                REQUIRE(public_key != nullptr);
                REQUIRE_FALSE(public_key->empty());
                REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
                REQUIRE(runtime.database.persistent_store.server_signing_keys.front().public_key == *public_key);

                auto const* server_signatures = object_member_as_object(*signatures, "example.org");
                REQUIRE(server_signatures != nullptr);
                auto const* encoded_signature = string_member(*server_signatures, "ed25519:auto");
                REQUIRE(encoded_signature != nullptr);

                auto const payload = merovingian::canonicaljson::serialize_canonical(
                    merovingian::canonicaljson::Value{clone_without_signatures(*object)});
                auto const signature = merovingian::events::matrix_bytes_from_base64(*encoded_signature);
                auto const public_key_bytes = merovingian::events::matrix_bytes_from_base64(*public_key);
                REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
                REQUIRE(signature.size() == crypto_sign_BYTES);
                REQUIRE(public_key_bytes.size() == crypto_sign_PUBLICKEYBYTES);
                REQUIRE(crypto_sign_verify_detached(
                            reinterpret_cast<unsigned char const*>(signature.data()),
                            reinterpret_cast<unsigned char const*>(payload.output.data()), payload.output.size(),
                            reinterpret_cast<unsigned char const*>(public_key_bytes.data())) == 0);
                REQUIRE(response.body.find("secret") == std::string::npos);
            }
        }
    }
}

SCENARIO("Homeserver routes signed inbound federation transactions through runtime policy", "[integration][federation]")
{
    GIVEN("a started runtime with a known remote server")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        merovingian::federation::upsert_remote(runtime.federation, remote_for(origin, key_id, token));
        auto const target = std::string{"/_matrix/federation/v1/send/txn123"};
        auto const body = signed_json_pdu(origin, key_id, token);
        auto const authorization = federation_authorization(origin, key_id, token, "PUT", target, body);

        WHEN("a signed federation request reaches the local router")
        {
            auto const response =
                merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, authorization, body});

            THEN("the transaction is accepted and recorded")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == R"({"pdus":{}})");
                REQUIRE(runtime.federation.accepted_transactions.size() == 1U);
                REQUIRE(runtime.federation.accepted_transactions.front().origin == origin);
                REQUIRE(runtime.federation.audit_events.size() == 1U);
                REQUIRE(merovingian::federation::federation_audit_is_safe(runtime.federation));
            }
        }
    }
}

SCENARIO("Homeserver rejects malformed overflow and private-address federation requests",
         "[integration][federation][security]")
{
    GIVEN("a started runtime with one private-address remote")
    {
        auto started = merovingian::homeserver::start_runtime(federation_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const origin = std::string{"matrix.example.org"};
        auto const key_id = std::string{"ed25519:auto"};
        auto const token = std::string{"verify-token"};
        auto remote = remote_for(origin, key_id, token);
        remote.discovery.resolved_addresses = {"127.0.0.1"};
        merovingian::federation::upsert_remote(runtime.federation, remote);
        auto const target = std::string{"/_matrix/federation/v1/send/txn123"};
        auto const body = signed_json_pdu(origin, key_id, token);
        auto const authorization = federation_authorization(origin, key_id, token, "PUT", target, body);
        auto const overflow_authorization =
            origin + "|" + key_id + "|sig:v1:ignored|example.org|184467440737095516160|canonical";
        auto const uncanonical_authorization =
            federation_authorization(origin, key_id, token, "PUT", target, body, "uncanonical");

        WHEN("malformed overflow uncanonical and private-address requests are routed")
        {
            auto const malformed =
                merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, "not-enough-fields", body});
            auto const overflow = merovingian::homeserver::handle_local_http_request(
                runtime, {"PUT", target, overflow_authorization, body});
            auto const uncanonical = merovingian::homeserver::handle_local_http_request(
                runtime, {"PUT", target, uncanonical_authorization, body});
            auto const private_remote =
                merovingian::homeserver::handle_local_http_request(runtime, {"PUT", target, authorization, body});

            THEN("all fail closed before accepting a transaction")
            {
                REQUIRE(malformed.status == 401U);
                REQUIRE(malformed.body == "malformed federation authorization");
                REQUIRE(overflow.status == 401U);
                REQUIRE(overflow.body == "malformed federation authorization");
                REQUIRE(uncanonical.status == 403U);
                REQUIRE(uncanonical.body == "remote address is private or loopback");
                REQUIRE(private_remote.status == 403U);
                REQUIRE(private_remote.body == "remote address is private or loopback");
                REQUIRE(runtime.federation.accepted_transactions.empty());
            }
        }
    }
}

