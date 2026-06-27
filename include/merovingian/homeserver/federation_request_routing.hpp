// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/local_http_router.hpp"

#include <string>

namespace merovingian::homeserver
{

// Extracts the room ID from an inbound federation HTTP request for worker
// shard routing.
//
// Room-scoped federation endpoints embed the room ID in the path (e.g.
// /_matrix/federation/v1/state/{roomId}). PUT /send/{txnId} carries the room
// ID inside the first PDU of the transaction body. Non-room endpoints
// (key server, profile queries, directory queries, etc.) return an empty
// string, which the caller routes to shard 0.
[[nodiscard]] auto federation_worker_room_id_from_request(LocalHttpRequest const& request) -> std::string;

} // namespace merovingian::homeserver
