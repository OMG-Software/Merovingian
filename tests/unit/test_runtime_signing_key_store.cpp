// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for the multi-key aware RuntimeSigningKeyStore and its interaction
// with crypto::sign_for_server.

#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/runtime_multikey_ed25519_provider.hpp"
#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/homeserver/runtime_signing_key_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian;

[[nodiscard]] auto make_test_key(std::string server_name, std::string key_id)
    -> std::pair<database::PersistentServerSigningKey, crypto::Ed25519Keypair>
{
    auto keypair = crypto::generate_ed25519_keypair().value();
    auto const public_key_view =
        std::string_view{reinterpret_cast<char const*>(keypair.public_key.data()), keypair.public_key.size()};
    auto const secret_key_view = std::string_view{reinterpret_cast<char const*>(keypair.secret_key.bytes().data()),
                                                  keypair.secret_key.bytes().size()};

    auto record = database::PersistentServerSigningKey{
        std::move(server_name),
        std::move(key_id),
        events::matrix_base64_from_bytes(public_key_view),
        std::numeric_limits<std::uint64_t>::max(),
        events::matrix_base64_from_bytes(secret_key_view),
    };
    return {std::move(record), std::move(keypair)};
}

// Provider secrets are core::SecretBuffer (move-only, mlocked), so each caller
// takes its own locked copy rather than sharing one plain array.
[[nodiscard]] auto secret_copy(crypto::Ed25519Keypair const& keypair) -> core::SecretBuffer
{
    return core::SecretBuffer{keypair.secret_key.bytes()};
}

[[nodiscard]] auto public_key_string(crypto::Ed25519Keypair const& keypair) -> std::string
{
    return std::string{reinterpret_cast<char const*>(keypair.public_key.data()), keypair.public_key.size()};
}

class FailingForKeyProvider final : public crypto::Ed25519Provider
{
public:
    FailingForKeyProvider(std::string fail_key_id, crypto::Ed25519Provider& fallback)
        : fail_key_id_{std::move(fail_key_id)}
        , fallback_{&fallback}
    {
    }

    [[nodiscard]] auto sign(crypto::Ed25519SecretKeyHandle const& key, std::string_view message)
        -> crypto::SignatureResult override
    {
        if (key.key_id == fail_key_id_)
        {
            return {crypto::Ed25519Signature{}, "injected signing failure"};
        }
        return fallback_->sign(key, message);
    }

    [[nodiscard]] auto verify(crypto::Ed25519PublicKey const& public_key, std::string_view message,
                              crypto::Ed25519Signature const& signature) -> crypto::VerificationResult override
    {
        return fallback_->verify(public_key, message, signature);
    }

private:
    std::string fail_key_id_{};
    crypto::Ed25519Provider* fallback_{};
};

} // namespace

SCENARIO("RuntimeSigningKeyStore exposes all usable active keys for the local server",
         "[homeserver][signing][multi-key]")
{
    GIVEN("two active keys, a legacy key, a key for another server, and a key with an invalid public key")
    {
        auto const server_name = std::string{"example.org"};
        auto const [active_a, keypair_a] = make_test_key(server_name, "ed25519:a0b1c2d3");
        auto const [active_b, keypair_b] = make_test_key(server_name, "ed25519:e4f5a6b7");
        auto const [legacy_key, unused_legacy] = make_test_key(server_name, "ed25519:auto");
        std::ignore = unused_legacy;
        auto const [other_server, unused_other] = make_test_key("other.example", "ed25519:11111111");
        std::ignore = unused_other;
        auto invalid_public = active_a;
        invalid_public.key_id = "ed25519:ffffffff";
        invalid_public.public_key = "not-valid-base64!!!";

        auto store = homeserver::RuntimeSigningKeyStore{
            server_name, std::vector{active_a, active_b, legacy_key, other_server, invalid_public}
        };

        WHEN("active_keys_for_server is queried for the local server")
        {
            auto const keys = store.active_keys_for_server(server_name);

            THEN("only the two usable local active keys are returned, in insertion order")
            {
                REQUIRE(keys.size() == 2U);
                REQUIRE(keys[0].key_id == active_a.key_id);
                REQUIRE(keys[0].public_key.bytes == public_key_string(keypair_a));
                REQUIRE(keys[1].key_id == active_b.key_id);
                REQUIRE(keys[1].public_key.bytes == public_key_string(keypair_b));
            }
        }

        WHEN("active_key_for_server is queried for the local server")
        {
            auto const result = store.active_key_for_server(server_name);

            THEN("the first usable active key is returned")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.key.key_id == active_a.key_id);
            }
        }

        WHEN("the store is queried for a different server")
        {
            auto const keys = store.active_keys_for_server("other.example");

            THEN("no keys are returned")
            {
                REQUIRE(keys.empty());
            }
        }
    }
}

SCENARIO("sign_for_server falls back to the next active key when the preferred key fails",
         "[homeserver][signing][multi-key]")
{
    GIVEN("two active keys where the provider rejects the first key_id")
    {
        auto const server_name = std::string{"example.org"};
        auto const [active_a, keypair_a] = make_test_key(server_name, "ed25519:a0b1c2d3");
        auto const [active_b, keypair_b] = make_test_key(server_name, "ed25519:e4f5a6b7");
        std::ignore = keypair_a;

        auto real_provider = crypto::RuntimeMultiKeyEd25519Provider{
            [&] {
                auto keys = std::vector<std::pair<std::string, core::SecretBuffer>>{};
                keys.emplace_back(active_a.key_id, secret_copy(keypair_a));
                keys.emplace_back(active_b.key_id, secret_copy(keypair_b));
                return keys;
            }()
        };
        auto failing_provider = FailingForKeyProvider{active_a.key_id, real_provider};

        auto store = homeserver::RuntimeSigningKeyStore{
            server_name, std::vector{active_a, active_b}
        };

        WHEN("a message is signed")
        {
            auto const result = crypto::sign_for_server(store, failing_provider, server_name, "hello multi-key");

            THEN("signing succeeds using the second key")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.key_id == active_b.key_id);
                REQUIRE_FALSE(result.signature.bytes.empty());
            }
        }
    }
}

SCENARIO("sign_for_server produces a verifiable signature with a chosen active key", "[homeserver][signing][multi-key]")
{
    GIVEN("two active keys backed by a real multi-key provider")
    {
        auto const server_name = std::string{"example.org"};
        auto const [active_a, keypair_a] = make_test_key(server_name, "ed25519:a0b1c2d3");
        auto const [active_b, keypair_b] = make_test_key(server_name, "ed25519:e4f5a6b7");

        auto provider = crypto::RuntimeMultiKeyEd25519Provider{
            [&] {
                auto keys = std::vector<std::pair<std::string, core::SecretBuffer>>{};
                keys.emplace_back(active_a.key_id, secret_copy(keypair_a));
                keys.emplace_back(active_b.key_id, secret_copy(keypair_b));
                return keys;
            }()
        };
        auto store = homeserver::RuntimeSigningKeyStore{
            server_name, std::vector{active_a, active_b}
        };

        WHEN("a message is signed")
        {
            auto const message = std::string{"test message"};
            auto const result = crypto::sign_for_server(store, provider, server_name, message);

            THEN("the signature verifies against the first active key's public key")
            {
                REQUIRE(result.error.empty());
                REQUIRE(result.key_id == active_a.key_id);
                auto const verified = crypto::ed25519_verify(crypto::Ed25519PublicKey{public_key_string(keypair_a)},
                                                             message, result.signature);
                REQUIRE(verified.valid);
            }
        }
    }
}
