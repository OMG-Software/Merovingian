// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/crypto/ipc_stream_cipher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace
{

// A blocking, thread-safe byte FIFO used to simulate one direction of the IPC
// pipe between two IpcStreamCipher instances running on separate threads
// (the constructor performs a synchronous handshake, so client and server
// must run concurrently to rendezvous).
struct ByteQueue final
{
    std::mutex mutex{};
    std::condition_variable cv{};
    std::vector<std::uint8_t> data{};

    auto push(void const* buffer, std::size_t len) -> bool
    {
        auto const lock = std::lock_guard{mutex};
        auto const* bytes = static_cast<unsigned char const*>(buffer);
        data.insert(data.end(), bytes, bytes + len);
        cv.notify_all();
        return true;
    }

    auto pop(void* buffer, std::size_t len) -> bool
    {
        auto lock = std::unique_lock{mutex};
        cv.wait(lock, [this, len] {
            return data.size() >= len;
        });
        std::memcpy(buffer, data.data(), len);
        data.erase(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(len));
        return true;
    }
};

[[nodiscard]] auto test_auth_key(unsigned char seed_byte) -> merovingian::crypto::IpcAuthKey
{
    auto key_material = std::array<std::uint8_t, 32U>{};
    key_material.fill(seed_byte);
    auto key = merovingian::crypto::derive_ipc_auth_key(key_material);
    REQUIRE(key.has_value());
    return *key;
}

} // namespace

// Regression coverage for #419/#432. Before this change, IpcStreamCipher had
// no test coverage at all: the crypto_kx_keypair() return value was ignored
// (a fail-open-shaped path — see #432) and the secretstream State was never
// wiped on destruction (crypto/AGENTS.md rule 7 — see #419). This scenario
// establishes the baseline correctness the fix must not regress: a full
// client/server handshake followed by an encrypt/decrypt round trip.
SCENARIO("IpcStreamCipher completes a client/server handshake and round-trips an encrypted frame",
         "[crypto][ipc][security]")
{
    GIVEN("a client and server cipher sharing one duplex byte pipe and the same auth key")
    {
        auto client_to_server = ByteQueue{};
        auto server_to_client = ByteQueue{};
        auto const auth_key = test_auth_key(0x42U);

        auto client_cipher = std::unique_ptr<merovingian::crypto::IpcStreamCipher>{};
        auto server_cipher = std::unique_ptr<merovingian::crypto::IpcStreamCipher>{};

        WHEN("both sides perform the handshake concurrently")
        {
            auto client_thread = std::thread{[&] {
                client_cipher = std::make_unique<merovingian::crypto::IpcStreamCipher>(
                    merovingian::crypto::IpcStreamCipher::Role::client, auth_key,
                    [&](void const* buffer, std::size_t len) {
                        return client_to_server.push(buffer, len);
                    },
                    [&](void* buffer, std::size_t len) {
                        return server_to_client.pop(buffer, len);
                    });
            }};
            auto server_thread = std::thread{[&] {
                server_cipher = std::make_unique<merovingian::crypto::IpcStreamCipher>(
                    merovingian::crypto::IpcStreamCipher::Role::server, auth_key,
                    [&](void const* buffer, std::size_t len) {
                        return server_to_client.push(buffer, len);
                    },
                    [&](void* buffer, std::size_t len) {
                        return client_to_server.pop(buffer, len);
                    });
            }};
            client_thread.join();
            server_thread.join();

            THEN("both sides construct successfully")
            {
                REQUIRE(client_cipher != nullptr);
                REQUIRE(server_cipher != nullptr);
            }

            THEN("a frame encrypted by the client decrypts correctly on the server")
            {
                REQUIRE(client_cipher != nullptr);
                REQUIRE(server_cipher != nullptr);
                auto const plaintext = std::array<std::uint8_t, 5U>{'h', 'e', 'l', 'l', 'o'};
                auto ciphertext = std::vector<std::uint8_t>(client_cipher->ciphertext_size(plaintext.size()));
                REQUIRE(client_cipher->encrypt(plaintext, ciphertext));

                auto decrypted = std::vector<char>(plaintext.size());
                REQUIRE(server_cipher->decrypt(ciphertext, decrypted));
                REQUIRE(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0);
            }

            THEN("a frame encrypted by the server decrypts correctly on the client")
            {
                REQUIRE(client_cipher != nullptr);
                REQUIRE(server_cipher != nullptr);
                auto const plaintext = std::array<std::uint8_t, 7U>{'r', 'e', 's', 'p', 'o', 'n', 's'};
                auto ciphertext = std::vector<std::uint8_t>(server_cipher->ciphertext_size(plaintext.size()));
                REQUIRE(server_cipher->encrypt(plaintext, ciphertext));

                auto decrypted = std::vector<char>(plaintext.size());
                REQUIRE(client_cipher->decrypt(ciphertext, decrypted));
                REQUIRE(std::memcmp(decrypted.data(), plaintext.data(), plaintext.size()) == 0);
            }
        }
    }
}

// #432: crypto_kx_keypair()'s failure path is not independently triggerable
// through the public API (libsodium's implementation cannot fail under
// normal conditions), so this exercises the adjacent fail-closed guarantee
// that the same defence-in-depth principle protects: a handshake that
// completes the KX exchange but fails mutual authentication (mismatched auth
// keys) must fail closed on both sides, never silently proceed with garbage
// or unauthenticated keys.
SCENARIO("IpcStreamCipher fails closed when the two sides use different auth keys", "[crypto][ipc][security]")
{
    GIVEN("a client and server with mismatched auth keys")
    {
        auto client_to_server = ByteQueue{};
        auto server_to_client = ByteQueue{};
        auto const client_key = test_auth_key(0x11U);
        auto const server_key = test_auth_key(0x22U);

        auto client_threw = false;
        auto server_threw = false;

        WHEN("both sides attempt the handshake concurrently")
        {
            auto client_thread = std::thread{[&] {
                try
                {
                    auto cipher = merovingian::crypto::IpcStreamCipher{
                        merovingian::crypto::IpcStreamCipher::Role::client, client_key,
                        [&](void const* buffer, std::size_t len) {
                            return client_to_server.push(buffer, len);
                        },
                        [&](void* buffer, std::size_t len) {
                            return server_to_client.pop(buffer, len);
                        }};
                }
                catch (std::runtime_error const&)
                {
                    client_threw = true;
                }
            }};
            auto server_thread = std::thread{[&] {
                try
                {
                    auto cipher = merovingian::crypto::IpcStreamCipher{
                        merovingian::crypto::IpcStreamCipher::Role::server, server_key,
                        [&](void const* buffer, std::size_t len) {
                            return server_to_client.push(buffer, len);
                        },
                        [&](void* buffer, std::size_t len) {
                            return client_to_server.pop(buffer, len);
                        }};
                }
                catch (std::runtime_error const&)
                {
                    server_threw = true;
                }
            }};
            client_thread.join();
            server_thread.join();

            THEN("both sides reject the handshake rather than proceeding with unauthenticated keys")
            {
                REQUIRE(client_threw);
                REQUIRE(server_threw);
            }
        }
    }
}
