// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/runtime_signing_key_store.hpp"

#include "merovingian/events/event_signer.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

RuntimeSigningKeyStore::RuntimeSigningKeyStore(std::string server_name,
                                               std::vector<database::PersistentServerSigningKey> keys)
    : server_name_{std::move(server_name)}
    , keys_{std::move(keys)}
{
}

RuntimeSigningKeyStore::RuntimeSigningKeyStore(std::string server_name, database::PersistentServerSigningKey key)
    : server_name_{std::move(server_name)}
    , keys_{std::vector{std::move(key)}}
{
}

auto RuntimeSigningKeyStore::active_key_for_server(std::string_view server_name) -> crypto::SigningKeyLookupResult
{
    if (server_name != server_name_)
    {
        return {{}, "signing key not found"};
    }
    auto keys = active_keys_for_server(server_name);
    if (keys.empty())
    {
        return {{}, "signing key not found"};
    }
    return {std::move(keys.front()), {}};
}

auto RuntimeSigningKeyStore::active_keys_for_server(std::string_view server_name)
    -> std::vector<crypto::SigningKeyRecord>
{
    if (server_name != server_name_)
    {
        return {};
    }

    auto result = std::vector<crypto::SigningKeyRecord>{};
    result.reserve(keys_.size());
    for (auto const& key : keys_)
    {
        if (key.server_name != server_name_ || key.key_id == "ed25519:auto" || key.public_key.empty())
        {
            continue;
        }
        auto public_key = events::matrix_bytes_from_base64(key.public_key);
        if (public_key.empty())
        {
            continue;
        }
        auto record = crypto::SigningKeyRecord{key.server_name, key.key_id,
                                               crypto::Ed25519PublicKey{std::move(public_key)}, true};
        if (!crypto::signing_key_record_is_usable(record))
        {
            continue;
        }
        result.push_back(std::move(record));
    }
    return result;
}

} // namespace merovingian::homeserver
