// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::media
{

// Operator-selectable disposition for a class of media (local upload or
// remote/federated fetch), configured via `security.media.local_upload_policy`
// and `security.media.remote_fetch_media_policy`:
//   allow            - accept unconditionally; the scanner verdict is ignored.
//   allow_after_scan - accept only when the scanner verdict is clean (the
//                      historical, only, behaviour before this policy existed).
//   quarantine       - always hold for manual admin review, regardless of
//                      the scanner verdict.
//   deny             - reject unconditionally; this class of media is disabled.
enum class MediaAcceptancePolicy
{
    allow,
    allow_after_scan,
    quarantine,
    deny,
};

} // namespace merovingian::media
