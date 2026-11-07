// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/Ed25519PublicKey.hpp"

#include <string>

namespace merovingian::crypto
{

struct SigningKeyRecord final
{
    std::string server_name{};
    std::string key_id{};
    Ed25519PublicKey public_key{};
    bool active{false};
};

} // namespace merovingian::crypto
