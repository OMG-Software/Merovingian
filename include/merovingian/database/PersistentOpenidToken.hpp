// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <string>

namespace merovingian::database
{

// A short-lived OpenID token minted by `POST
// /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19 CS
// API §OpenID) and redeemed by `GET /_matrix/federation/v1/openid/userinfo`
// (SS API §OpenID). Deliberately a table of its own, disjoint from
// PersistentAccessToken/access_tokens: this token authenticates nothing on
// the client-server surface -- its only valid use is the federation
// userinfo lookup -- so keeping it out of the access-token store and its
// lookup path is what prevents it from being replayed as a client-server
// bearer credential (see docs/threat-model.md). Unlike access tokens, every
// row has a finite expiry (the spec's `expires_in` is required), so
// expires_at is a plain time_point rather than optional.
struct PersistentOpenidToken final
{
    std::string user_id{};
    std::string token_hash{};
    std::chrono::system_clock::time_point expires_at{};
};

} // namespace merovingian::database
