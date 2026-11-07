// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Matrix account-data row. Per-room account data is identified by a
// non-empty `room_id`; an empty `room_id` denotes global account data.
// The runtime keeps both classes in the same in-memory collection;
// they are persisted to separate backend tables (`account_data` /
// `room_account_data`) because the v1 schema's primary key on
// `account_data` did not include `room_id`.
struct PersistentAccountData final
{
    std::string user_id{};
    std::string room_id{};
    std::string event_type{};
    std::string content_json{};
    std::uint64_t stream_id{0U};
};

} // namespace merovingian::database
