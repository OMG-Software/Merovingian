// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PersistentServerSigningKey.hpp"

#include "merovingian/core/SecretBuffer.hpp"

#include <span>
#include <string>
#include <utility>

namespace merovingian::database
{

namespace
{

    // Wipe a string's characters in place before it is dropped or overwritten.
    // shrink_to_fit is deliberately not called: it may reallocate, which would
    // copy the bytes we are trying to erase into a fresh buffer and free the
    // old one unwiped.
    auto wipe_secret_string(std::string& value) noexcept -> void
    {
        core::secure_zero(std::as_writable_bytes(std::span{value}));
        value.clear();
    }

} // namespace

PersistentServerSigningKey::PersistentServerSigningKey(std::string server_name_value, std::string key_id_value,
                                                       std::string public_key_value, std::uint64_t valid_until_ts_value,
                                                       std::string secret_key_value)
    : server_name{std::move(server_name_value)}
    , key_id{std::move(key_id_value)}
    , public_key{std::move(public_key_value)}
    , valid_until_ts{valid_until_ts_value}
    , secret_key{std::move(secret_key_value)}
{
}

PersistentServerSigningKey::PersistentServerSigningKey(PersistentServerSigningKey const& other)
    : server_name{other.server_name}
    , key_id{other.key_id}
    , public_key{other.public_key}
    , valid_until_ts{other.valid_until_ts}
    , secret_key{other.secret_key}
    , expired_ts{other.expired_ts}
{
}

auto PersistentServerSigningKey::operator=(PersistentServerSigningKey const& other) -> PersistentServerSigningKey&
{
    if (this != &other)
    {
        // Wipe first: assigning over the old secret would otherwise release its
        // buffer (or leave its tail) without erasing it.
        wipe_secret_string(secret_key);
        server_name = other.server_name;
        key_id = other.key_id;
        public_key = other.public_key;
        valid_until_ts = other.valid_until_ts;
        secret_key = other.secret_key;
        expired_ts = other.expired_ts;
    }
    return *this;
}

PersistentServerSigningKey::PersistentServerSigningKey(PersistentServerSigningKey&& other) noexcept
    : server_name{std::move(other.server_name)}
    , key_id{std::move(other.key_id)}
    , public_key{std::move(other.public_key)}
    , valid_until_ts{other.valid_until_ts}
    , secret_key{std::move(other.secret_key)}
    , expired_ts{other.expired_ts}
{
    // A moved-from std::string is valid but unspecified: with the small-string
    // optimisation it may still hold the original characters. Wipe it.
    wipe_secret_string(other.secret_key);
}

auto PersistentServerSigningKey::operator=(PersistentServerSigningKey&& other) noexcept -> PersistentServerSigningKey&
{
    if (this != &other)
    {
        wipe_secret_string(secret_key);
        server_name = std::move(other.server_name);
        key_id = std::move(other.key_id);
        public_key = std::move(other.public_key);
        valid_until_ts = other.valid_until_ts;
        secret_key = std::move(other.secret_key);
        expired_ts = other.expired_ts;
        wipe_secret_string(other.secret_key);
    }
    return *this;
}

PersistentServerSigningKey::~PersistentServerSigningKey()
{
    wipe_secret_string(secret_key);
}

} // namespace merovingian::database
