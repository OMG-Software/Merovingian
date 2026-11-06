// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// PHASE-B: forwarding includes, removed when consumers include the new headers directly.
#include "merovingian/sync/ExtAccountDataRequest.hpp"
#include "merovingian/sync/ExtAccountDataResponse.hpp"
#include "merovingian/sync/ExtE2eeRequest.hpp"
#include "merovingian/sync/ExtE2eeResponse.hpp"
#include "merovingian/sync/ExtReceiptsRequest.hpp"
#include "merovingian/sync/ExtReceiptsResponse.hpp"
#include "merovingian/sync/ExtToDeviceRequest.hpp"
#include "merovingian/sync/ExtToDeviceResponse.hpp"
#include "merovingian/sync/ExtTypingRequest.hpp"
#include "merovingian/sync/ExtTypingResponse.hpp"
#include "merovingian/sync/SlidingSyncConnectionState.hpp"
#include "merovingian/sync/SlidingSyncExtensionRequests.hpp"
#include "merovingian/sync/SlidingSyncExtensionResponses.hpp"
#include "merovingian/sync/SlidingSyncFilters.hpp"
#include "merovingian/sync/SlidingSyncHero.hpp"
#include "merovingian/sync/SlidingSyncLimits.hpp"
#include "merovingian/sync/SlidingSyncList.hpp"
#include "merovingian/sync/SlidingSyncListResponse.hpp"
#include "merovingian/sync/SlidingSyncOp.hpp"
#include "merovingian/sync/SlidingSyncPendingResponse.hpp"
#include "merovingian/sync/SlidingSyncRange.hpp"
#include "merovingian/sync/SlidingSyncRequest.hpp"
#include "merovingian/sync/SlidingSyncResponse.hpp"
#include "merovingian/sync/SlidingSyncRoomResponse.hpp"
#include "merovingian/sync/SlidingSyncRoomSubscription.hpp"

#include <cstddef>
#include <cstdint>

// MSC4186 Simplified Sliding Sync — request/response types.
// Spec: https://github.com/matrix-org/matrix-spec-proposals/blob/main/proposals/4186-simplified-sliding-sync.md
//
// Served at: POST /_matrix/client/unstable/org.matrix.msc4186/sync
// Advertised via: GET /_matrix/client/versions → unstable_features["org.matrix.msc4186"] and
// unstable_features["org.matrix.simplified_msc3575"]

namespace merovingian::sync
{

// ──────────────────────────────────────────────────────────────────────────────
// Request limits
// ──────────────────────────────────────────────────────────────────────────────

// Source-compatible defaults for standalone callers and existing tests.
inline constexpr std::uint64_t sliding_sync_max_timeline_limit{100U};
inline constexpr std::size_t sliding_sync_max_room_subscriptions{256U};
inline constexpr std::size_t sliding_sync_max_required_state_entries{256U};

} // namespace merovingian::sync
