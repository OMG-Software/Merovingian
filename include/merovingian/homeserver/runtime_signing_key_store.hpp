// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/signing_service.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

// Production SigningKeyStore backed by the persisted server signing-key rows.
//
// A single instance can publish every currently-active key for the local server,
// which lets crypto::sign_for_server iterate over multiple valid keys during
// rotation or multi-key deployments. Callers that only need the preferred key
// can pass a one-element vector.
class RuntimeSigningKeyStore final : public crypto::SigningKeyStore
{
public:
    explicit RuntimeSigningKeyStore(std::string server_name, std::vector<database::PersistentServerSigningKey> keys);
    explicit RuntimeSigningKeyStore(std::string server_name, database::PersistentServerSigningKey key);

    [[nodiscard]] auto active_key_for_server(std::string_view server_name) -> crypto::SigningKeyLookupResult override;
    [[nodiscard]] auto active_keys_for_server(std::string_view server_name)
        -> std::vector<crypto::SigningKeyRecord> override;

private:
    std::string server_name_{};
    std::vector<database::PersistentServerSigningKey> keys_{};
};

} // namespace merovingian::homeserver
