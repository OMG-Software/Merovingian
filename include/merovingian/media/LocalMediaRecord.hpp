// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/LocalMediaState.hpp"

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct LocalMediaRecord final
{
    std::string media_id{};
    std::string owner_user_id{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    std::string storage_id{};
    LocalMediaState state{LocalMediaState::available};
    std::string quarantine_reason{};
    // True when the media was uploaded before the authenticated-media upgrade
    // and may still be served by the legacy unauthenticated v3 endpoints.
    // New uploads are minted with false, so /_matrix/media/v3/download and
    // /thumbnail fail closed to 404 while /_matrix/client/v1/media/... remains
    // available (Matrix v1.19 authenticated media, security audit M05).
    bool legacy_endpoint_visible{false};
    // True for a copy of remote media held in the remote media cache (ADR-0120), which is charged
    // to the cache's budget and never to local quotas. Set when the record is created, from the
    // upload request, and on hydration by is_remote_cache_owner; never inferred from the owner
    // string alone, which a local account could imitate (security audit run-1).
    bool from_remote_fetch{false};
    // The `filename` the upload was made with, or the remote server's
    // Content-Disposition filename; empty when there was none. Served back in
    // Content-Disposition on download (ADR-0211).
    std::string upload_name{};
};

} // namespace merovingian::media
