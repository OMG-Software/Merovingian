// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/ipc_stream_cipher.hpp"

#include <array>
#include <cstring>
#include <span>
#include <stdexcept>

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    template <typename Range>
    auto secure_zero(Range& range) noexcept -> void
    {
        if (!range.empty())
        {
            sodium_memzero(range.data(), range.size());
        }
    }

} // namespace

struct IpcStreamCipher::State
{
    crypto_secretstream_xchacha20poly1305_state push{};
    crypto_secretstream_xchacha20poly1305_state pull{};
};

IpcStreamCipher::IpcStreamCipher(Role const role, IpcAuthKey auth_key,
                                 std::function<bool(void const*, std::size_t)> send_fn,
                                 std::function<bool(void*, std::size_t)> recv_fn)
    : state_{std::make_unique<State>()}
{
    if (!sodium_is_ready())
    {
        throw std::runtime_error{"ipc: libsodium not initialised"};
    }

    auto my_pk = std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>{};
    auto my_sk = std::array<std::uint8_t, crypto_kx_SECRETKEYBYTES>{};
    crypto_kx_keypair(my_pk.data(), my_sk.data());

    auto peer_pk = std::array<std::uint8_t, crypto_kx_PUBLICKEYBYTES>{};

    if (!send_fn(my_pk.data(), my_pk.size()) || !recv_fn(peer_pk.data(), peer_pk.size()))
    {
        secure_zero(my_sk);
        throw std::runtime_error{"ipc: public key exchange failed"};
    }

    auto const role_byte = static_cast<std::uint8_t>(role == Role::server ? 0x01U : 0x02U);
    auto const peer_role_byte = static_cast<std::uint8_t>(role == Role::server ? 0x02U : 0x01U);

    auto mac_msg = std::array<std::uint8_t, 1U + crypto_kx_PUBLICKEYBYTES + crypto_kx_PUBLICKEYBYTES>{};
    mac_msg[0U] = role_byte;
    std::memcpy(mac_msg.data() + 1U, my_pk.data(), crypto_kx_PUBLICKEYBYTES);
    std::memcpy(mac_msg.data() + 1U + crypto_kx_PUBLICKEYBYTES, peer_pk.data(), crypto_kx_PUBLICKEYBYTES);

    auto my_mac = std::array<std::uint8_t, crypto_auth_BYTES>{};
    crypto_auth(my_mac.data(), mac_msg.data(), mac_msg.size(), auth_key.bytes.data());

    auto peer_mac = std::array<std::uint8_t, crypto_auth_BYTES>{};
    if (!send_fn(my_mac.data(), my_mac.size()) || !recv_fn(peer_mac.data(), peer_mac.size()))
    {
        secure_zero(my_sk);
        secure_zero(my_mac);
        secure_zero(auth_key.bytes);
        throw std::runtime_error{"ipc: auth MAC exchange failed"};
    }

    mac_msg[0U] = peer_role_byte;
    std::memcpy(mac_msg.data() + 1U, peer_pk.data(), crypto_kx_PUBLICKEYBYTES);
    std::memcpy(mac_msg.data() + 1U + crypto_kx_PUBLICKEYBYTES, my_pk.data(), crypto_kx_PUBLICKEYBYTES);
    if (crypto_auth_verify(peer_mac.data(), mac_msg.data(), mac_msg.size(), auth_key.bytes.data()) != 0)
    {
        secure_zero(my_sk);
        secure_zero(my_mac);
        secure_zero(peer_mac);
        secure_zero(auth_key.bytes);
        throw std::runtime_error{"ipc: peer authentication failed"};
    }
    secure_zero(my_mac);
    secure_zero(peer_mac);
    secure_zero(auth_key.bytes);

    auto rx = std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES>{};
    auto tx = std::array<std::uint8_t, crypto_kx_SESSIONKEYBYTES>{};
    auto const rc =
        (role == Role::server)
            ? crypto_kx_server_session_keys(rx.data(), tx.data(), my_pk.data(), my_sk.data(), peer_pk.data())
            : crypto_kx_client_session_keys(rx.data(), tx.data(), my_pk.data(), my_sk.data(), peer_pk.data());
    secure_zero(my_sk);
    secure_zero(my_pk);
    secure_zero(peer_pk);

    if (rc != 0)
    {
        secure_zero(rx);
        secure_zero(tx);
        throw std::runtime_error{"ipc: session key derivation failed"};
    }

    auto our_header = std::array<std::uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES>{};
    crypto_secretstream_xchacha20poly1305_init_push(&state_->push, our_header.data(), tx.data());
    secure_zero(tx);

    auto peer_header = std::array<std::uint8_t, crypto_secretstream_xchacha20poly1305_HEADERBYTES>{};
    if (role == Role::server)
    {
        if (!send_fn(our_header.data(), our_header.size()) || !recv_fn(peer_header.data(), peer_header.size()))
        {
            secure_zero(rx);
            throw std::runtime_error{"ipc: secretstream header exchange failed"};
        }
    }
    else
    {
        if (!recv_fn(peer_header.data(), peer_header.size()) || !send_fn(our_header.data(), our_header.size()))
        {
            secure_zero(rx);
            throw std::runtime_error{"ipc: secretstream header exchange failed"};
        }
    }

    if (crypto_secretstream_xchacha20poly1305_init_pull(&state_->pull, peer_header.data(), rx.data()) != 0)
    {
        secure_zero(rx);
        throw std::runtime_error{"ipc: secretstream pull init failed"};
    }

    secure_zero(rx);
    secure_zero(our_header);
    secure_zero(peer_header);
}

IpcStreamCipher::~IpcStreamCipher() = default;

auto IpcStreamCipher::ciphertext_size(std::size_t const plaintext_size) const noexcept -> std::size_t
{
    return plaintext_size + crypto_secretstream_xchacha20poly1305_ABYTES;
}

auto IpcStreamCipher::encrypt(std::span<std::uint8_t const> const plaintext,
                              std::span<std::uint8_t> const ciphertext) noexcept -> bool
{
    if (ciphertext.size() != ciphertext_size(plaintext.size()))
    {
        return false;
    }
    return crypto_secretstream_xchacha20poly1305_push(&state_->push, ciphertext.data(), nullptr, plaintext.data(),
                                                      plaintext.size(), nullptr, 0,
                                                      crypto_secretstream_xchacha20poly1305_TAG_MESSAGE) == 0;
}

auto IpcStreamCipher::decrypt(std::span<std::uint8_t const> const ciphertext, std::span<char> const plaintext) noexcept
    -> bool
{
    if (ciphertext.size() < crypto_secretstream_xchacha20poly1305_ABYTES ||
        plaintext.size() != ciphertext.size() - crypto_secretstream_xchacha20poly1305_ABYTES)
    {
        return false;
    }
    auto tag = std::uint8_t{};
    return crypto_secretstream_xchacha20poly1305_pull(&state_->pull, reinterpret_cast<std::uint8_t*>(plaintext.data()),
                                                      nullptr, &tag, ciphertext.data(), ciphertext.size(), nullptr,
                                                      0) == 0;
}

} // namespace merovingian::crypto
