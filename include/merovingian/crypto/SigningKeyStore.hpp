// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/SigningKeyLookupResult.hpp"
#include "merovingian/crypto/SigningKeyRecord.hpp"

#include <string_view>
#include <vector>

namespace merovingian::crypto
{

class SigningKeyStore
{
public:
    SigningKeyStore() = default;
    SigningKeyStore(SigningKeyStore const& other) = delete;
    auto operator=(SigningKeyStore const& other) -> SigningKeyStore& = delete;
    SigningKeyStore(SigningKeyStore&& other) noexcept = delete;
    auto operator=(SigningKeyStore&& other) noexcept -> SigningKeyStore& = delete;
    virtual ~SigningKeyStore() = default;

    [[nodiscard]] virtual auto active_key_for_server(std::string_view server_name) -> SigningKeyLookupResult = 0;

    // Returns every currently-active signing key for the requested server. The
    // default implementation delegates to active_key_for_server so existing
    // single-key stores continue to work; multi-key stores should override it.
    [[nodiscard]] virtual auto active_keys_for_server(std::string_view server_name) -> std::vector<SigningKeyRecord>;
};

} // namespace merovingian::crypto
