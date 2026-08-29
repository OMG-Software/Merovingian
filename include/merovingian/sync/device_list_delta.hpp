// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// One observer's device-list delta over a half-open sync-stream range.
struct DeviceListDelta final
{
    std::vector<std::string> changed{};
    std::vector<std::string> left{};
    // Highest `stream_id` seen for this observer within the range, or the
    // range's lower bound when the range held no changes. Callers advancing a
    // sync token need this even when they discard the lists themselves.
    std::uint64_t max_stream_id{0U};
};

// Collects the device-list changes `user` observes for stream ids in
// (from_sync_stream_id, to_sync_stream_id].
//
// Spec (client-server-api.md, "Extensions to /sync"): `changed` and `left` are
// lists of the user IDs whose devices changed, or with whom no encrypted room
// is shared any more, *since the previous sync response*. A user ID is
// therefore reported at most once across both lists, however many change rows
// the store holds for it in the range — the highest-stream-id row for that
// subject decides which list it lands in, so a user who changed and then left
// is reported only as having left.
//
// Results are sorted lexicographically so a given store state always produces
// the same response bytes.
[[nodiscard]] auto collect_device_list_delta(
    database::PersistentStore const& store, std::string_view user, std::uint64_t from_sync_stream_id,
    std::uint64_t to_sync_stream_id = std::numeric_limits<std::uint64_t>::max()) -> DeviceListDelta;

} // namespace merovingian::sync
