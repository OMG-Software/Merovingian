// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::identity
{

// One entry in the `public_keys` array of a store-invite response: the IS's
// long-term public key and the ephemeral public key it generated for this
// invite, each with a key_validity_url where joining servers can check it.
struct StoreInvitePublicKey final
{
    std::string public_key{};
    std::string key_validity_url{};
};

} // namespace merovingian::identity
