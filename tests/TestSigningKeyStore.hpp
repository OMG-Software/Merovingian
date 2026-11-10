// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/SigningKeyLookupResult.hpp"
#include "merovingian/crypto/SigningKeyRecord.hpp"
#include "merovingian/crypto/SigningKeyStore.hpp"

#include <string_view>
#include <utility>

namespace merovingian::federation::test
{

// A signing key store holding one key, for sign_event_for_server in PDU
// verification tests. The key is built from the same seed as the remote's
// FederationKeyRecord, so the signature verifies against the key the runtime
// holds.
class TestSigningKeyStore final : public merovingian::crypto::SigningKeyStore
{
public:
    explicit TestSigningKeyStore(merovingian::crypto::SigningKeyRecord key)
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
    merovingian::crypto::SigningKeyRecord key_;
};

} // namespace merovingian::federation::test
