// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::http
{

// Explicit client-server route tiers. The classification lives in
// rate_limit_tier_for() (src/http/rate_limit.cpp) as one greppable prefix
// table, and each tier's default policy lives in rate_limit_tier_default().
// Operators override a whole tier via `client_rate_limits.tier.<name>`
// config keys (auth_sensitive, media, sync, federation, admin, generic).
enum class RateLimitTier // no `final`: clang <= 18 rejects `final` on enums (C++26)
{
    // Unauthenticated credential/enumeration surface: /login, /register,
    // /refresh and every */requestToken route. These have no authenticated
    // user to key on, so the per-IP bucket is the only defense and the tier
    // default is tighter than the generic fallback.
    auth_sensitive,
    // Media download/thumbnail/upload, both the legacy /_matrix/media/ tree
    // and the authenticated /_matrix/client/v1/media/ tree.
    media,
    // /sync and the MSC4186 / simplified MSC3575 sliding-sync long-polls.
    sync,
    // /_matrix/federation/* routes reaching the client-server dispatcher.
    // Inbound federation on the federation listener is limited per verified
    // origin server name instead (see security.federation.per_origin_*).
    federation,
    // /_merovingian/admin/* operator surface.
    admin,
    // Every other client-server route.
    generic,
};

} // namespace merovingian::http
