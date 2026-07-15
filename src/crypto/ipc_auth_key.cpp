// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/ipc_auth_key.hpp"

#include <string_view>

#include <sodium.h>

namespace merovingian::crypto
{

IpcAuthKey::IpcAuthKey(IpcAuthKey const& other) noexcept
    : bytes(other.bytes)
{
}

auto IpcAuthKey::operator=(IpcAuthKey const& other) noexcept -> IpcAuthKey&
{
    if (this != &other)
    {
        sodium_memzero(bytes.data(), bytes.size());
        bytes = other.bytes;
    }
    return *this;
}

IpcAuthKey::IpcAuthKey(IpcAuthKey&& other) noexcept
    : bytes(other.bytes)
{
    sodium_memzero(other.bytes.data(), other.bytes.size());
}

auto IpcAuthKey::operator=(IpcAuthKey&& other) noexcept -> IpcAuthKey&
{
    if (this != &other)
    {
        sodium_memzero(bytes.data(), bytes.size());
        bytes = other.bytes;
        sodium_memzero(other.bytes.data(), other.bytes.size());
    }
    return *this;
}

IpcAuthKey::~IpcAuthKey()
{
    sodium_memzero(bytes.data(), bytes.size());
}

namespace
{

    // Domain separation label for the IPC channel auth key. Distinct from the
    // access-token HMAC labels (merovingian:access-token-hmac:*) so the derived
    // keys can never collide across cryptographic purposes.
    constexpr auto k_context = std::string_view{"merovingian:ipc-channel-auth:1"};

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

} // namespace

auto derive_ipc_auth_key(std::span<std::uint8_t const> master_key_material) noexcept -> std::optional<IpcAuthKey>
{
    if (!sodium_is_ready() || master_key_material.empty())
    {
        return std::nullopt;
    }

    auto key = IpcAuthKey{};
    if (crypto_generichash(key.bytes.data(), key.bytes.size(), master_key_material.data(), master_key_material.size(),
                           reinterpret_cast<unsigned char const*>(k_context.data()), k_context.size()) != 0)
    {
        return std::nullopt;
    }
    return key;
}

} // namespace merovingian::crypto