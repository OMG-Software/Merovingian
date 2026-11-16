// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Migration 002: a registered OAuth 2.0 client (`oauth_clients`). `metadata_json` is the accepted client metadata as
// `oauth::ClientMetadata::canonical_bytes` gives it; the row is written once and never changed, except
// `last_used_at_ms`, which `touch_oauth_client` moves at most once a day (ADR-0777). Times are milliseconds since
// the Unix epoch.
struct PersistentOAuthClient final
{
    std::string client_id{};
    std::string metadata_json{};
    std::uint64_t created_at_ms{0U};
    std::uint64_t last_used_at_ms{0U};
};

} // namespace merovingian::database
