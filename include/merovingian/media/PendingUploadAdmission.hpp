// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::media
{

// Whether `user_id` may upload content to `media_id` now, in the order the
// spec's errors are checked: content already there (409
// M_CANNOT_OVERWRITE_MEDIA when the user owns it, 403 otherwise), no live
// reservation (404 M_NOT_FOUND), a reservation made by someone else (403
// M_FORBIDDEN).
enum class PendingUploadAdmission
{
    accepted,
    already_uploaded,
    not_found,
    forbidden,
};

} // namespace merovingian::media
