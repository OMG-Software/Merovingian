// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <string>

namespace merovingian::database
{

// A short-lived, single-use SSO login token minted when the SSO redirect
// flow completes and redeemed by `POST /login` with `type: m.login.token`
// (Matrix v1.19 CS API §"Client login via SSO"). Deliberately a table of its
// own, disjoint from PersistentAccessToken/access_tokens, for the same
// reason PersistentOpenidToken is: this token authenticates nothing on the
// ordinary client-server surface beyond the single /login exchange, so
// keeping it out of the access-token store and its lookup path is what
// prevents it from being replayed as a bearer credential. `used` enforces
// single-use redemption (spec: "opaque token, suitable for use with
// m.login.token"). The `device_id` the eventual session binds to comes from
// the `POST /login` request body itself, exactly as it already does for
// `m.login.password` -- this row only needs to answer "which user".
struct PersistentLoginToken final
{
    std::string user_id{};
    std::string token_hash{};
    std::chrono::system_clock::time_point expires_at{};
    bool used{false};
};

} // namespace merovingian::database
