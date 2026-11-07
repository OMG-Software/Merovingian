// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/identity/StoreInvitePublicKey.hpp"

#include <string>
#include <vector>

namespace merovingian::identity
{

// Parsed `POST /_matrix/identity/v2/store-invite` response (200). Per the v1.19
// spec the IS — not the homeserver — generates the invite `token`, the
// redacted `display_name`, and the `public_keys` (long-term + ephemeral). The
// homeserver embeds the ephemeral public_key/key_validity_url in the
// `m.room.third_party_invite` event so joining servers can verify the invite
// signature via the IS.
struct StoreInviteResponse final
{
    std::string token{};
    std::string display_name{};
    std::vector<StoreInvitePublicKey> public_keys{};
};

} // namespace merovingian::identity
