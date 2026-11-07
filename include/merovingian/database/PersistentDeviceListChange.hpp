// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Device-list change observed by a syncing user. `change_type` is
// "changed" or "left" per the Matrix spec. `observer_user_id` is the
// local user whose /sync will surface this change; `subject_user_id`
// is the user whose device list changed.
struct PersistentDeviceListChange final
{
    std::uint64_t stream_id{0U};
    std::string observer_user_id{};
    std::string subject_user_id{};
    std::string change_type{"changed"};
};

} // namespace merovingian::database
