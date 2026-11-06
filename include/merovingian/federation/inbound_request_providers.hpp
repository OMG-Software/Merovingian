// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/event_table.hpp"
#include "merovingian/federation/FederationDirectory.hpp"
#include "merovingian/federation/FederationProfile.hpp"
#include "merovingian/federation/FederationRemoteRuntime.hpp"
#include "merovingian/federation/FederationThumbnailQuery.hpp"
#include "merovingian/federation/public_rooms.hpp"
#include "merovingian/federation/room_read_result.hpp"
#include "merovingian/media/LocalMediaDownloadResult.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::federation
{

// On-demand resolver for remote federation peers. The resolver is responsible
// for any discovery, network fetch, self-signature verification, and caching
// — the federation core only consumes the returned record. The returned
// runtime carries both the verified signing key and the resolved discovery
// state so the inbound bootstrap path can pass the SSRF/TLS policy on the
// first request from a previously-unknown remote. Returning std::nullopt
// signals that resolution failed and the request must be rejected.
using RemoteKeyResolver =
    std::function<std::optional<FederationRemoteRuntime>(std::string_view server_name, std::string_view key_id)>;

// Optional legacy hint for a genuinely network-free, complete peer resolution.
// A true answer must cover discovery metadata as well as the signing key: a
// fresh persistent key alone does not prove that the full resolver avoids DNS
// or HTTP. Production leaves this unset and uses cached_pdu_key_lookup for
// key-only PDU verification and known-peer rotation instead.
//
// When unset, every full resolution is charged. An embedded full-resolution
// cache may opt in, but must not use mere key freshness as the admission signal.
using RemoteKeyCacheProbe = std::function<bool(std::string_view server_name, std::string_view key_id)>;

// Resolves a room alias for an inbound federation
// `GET /_matrix/federation/v1/query/directory`. Optional: when unset the
// handler responds 501 Not Implemented. The alias is percent-decoded before
// being passed to the provider.
using DirectoryQueryProvider = std::function<FederationDirectory(std::string_view room_alias)>;

// Answers an inbound `GET` or `POST /_matrix/federation/v1/publicRooms` with its 200 response body, or
// nothing when the answer could not be had (a worker's relay to main failed: 503). Optional: when unset
// the handler responds 501 Not Implemented.
using PublicRoomsProvider = std::function<std::optional<std::string>(PublicRoomsRequest const& request)>;

// Resolves a local user's published profile for an inbound federation
// `GET /_matrix/federation/v1/query/profile`. Optional: when unset the
// handler responds 501 Not Implemented.
using ProfileQueryProvider = std::function<FederationProfile(std::string_view user_id)>;

// Server-blind E2EE federation query hooks. The two POST hooks take the
// request body and return the canonical-JSON response body; the devices hook
// takes the path user_id. An empty return signals failure. Optional: an unset
// hook makes the corresponding route respond 501 Not Implemented.
using DeviceKeysQueryProvider = std::function<std::string(std::string_view request_body)>;
using OneTimeKeysClaimProvider = std::function<std::string(std::string_view request_body)>;
using UserDevicesProvider = std::function<std::string(std::string_view user_id)>;

// Inbound event-graph query hooks. Each takes the parsed path component (and
// for `get_missing_events`, the request body) plus the X-Matrix-authenticated
// `origin` of the requesting server, and returns a `RoomReadResult`: the
// canonical-JSON response body on `ok`, `forbidden` when the origin has no
// joined user in the room and the room is not world readable (403
// M_FORBIDDEN, FED-2), `not_found` for an unknown room or event (404
// M_NOT_FOUND) and `malformed` for an unusable request body (400). The provider
// is where the origin-in-room check lives, so every process that serves the
// endpoint (main and the federation worker) enforces it. Optional: an unset
// hook makes the corresponding route respond 501 Not Implemented.
using EventQueryProvider = std::function<RoomReadResult(std::string_view event_id, std::string_view origin)>;
using StateQueryProvider =
    std::function<RoomReadResult(std::string_view room_id, std::string_view event_id, std::string_view origin)>;
using StateIdsQueryProvider =
    std::function<RoomReadResult(std::string_view room_id, std::string_view event_id, std::string_view origin)>;
// `GET /event_auth/{roomId}/{eventId}`: the room, the event whose auth chain is asked for, and the
// authenticated origin.
using EventAuthQueryProvider =
    std::function<RoomReadResult(std::string_view room_id, std::string_view event_id, std::string_view origin)>;
using MissingEventsQueryProvider =
    std::function<RoomReadResult(std::string_view room_id, std::string_view request_body, std::string_view origin)>;
// `GET /timestamp_to_event/{roomId}?ts=&dir=`: the room, the timestamp in milliseconds, the direction and
// the authenticated origin. The handler has already parsed `ts` and `dir`; the provider decides the
// access of the origin (`forbidden`) and finds the event (`not_found` when there is none).
using TimestampToEventQueryProvider = std::function<RoomReadResult(
    std::string_view room_id, std::int64_t ts, database::TimeDirection direction, std::string_view origin)>;

// Returns the canonical-JSON body for an inbound `GET /_matrix/federation/v1/hierarchy/{roomId}`
// request. The `room_id` path component is already percent-decoded; `suggested_only` reflects the
// `suggested_only` query parameter; `origin` is the authenticated requesting server, whose access
// to the room (and to each child) the provider judges. An empty return signals failure and the
// handler responds 404 M_NOT_FOUND. Optional: when unset the route responds 501 Not Implemented.
using SpaceHierarchyProvider =
    std::function<std::string(std::string_view room_id, bool suggested_only, std::string_view origin)>;

// Serves a local media file for an inbound `GET /_matrix/federation/v1/media/download/{mediaId}`
// request. The `media_id` path component is already percent-decoded. The handler maps a failed
// result to the appropriate Matrix error response (404 M_NOT_FOUND for missing media, 451 for
// quarantined media, etc.). Optional: when unset the route responds 501 Not Implemented.
using MediaDownloadProvider = std::function<media::LocalMediaDownloadResult(std::string_view media_id)>;

// Serves a thumbnail of local media for an inbound federation thumbnail request. The handler maps a
// failed result as for `MediaDownloadProvider` (404, 451, 504 M_NOT_YET_UPLOADED, ...). Optional:
// when unset the route responds 501 Not Implemented.
using MediaThumbnailProvider = std::function<media::LocalMediaDownloadResult(FederationThumbnailQuery const& query)>;

// Resolves the room version for a given room ID by consulting the local
// persistent state (typically the m.room.create event's content.room_version
// field). Returns a version string such as "10", "11", "12". When the room
// is unknown the resolver should return the current default ("12").
// Optional: when unset PDU parsing falls back to "12".
using RoomVersionResolver = std::function<std::string(std::string_view room_id)>;
// Optional provider for per-room server ACL enforcement (MSC4436). Returns
// true when the server is allowed to participate in the room, or when the
// room has no m.room.server_acl event. When unset, ACL checks are skipped.
using RoomServerAclProvider = std::function<bool(std::string_view room_id, std::string_view server_name)>;
// Why rules held outside the config refuse a server (an admin's scope-federation policy rule), empty when
// they do not. See operator_policy_refusal.
using ServerPolicyRefusalProvider = std::function<std::string(std::string_view server_name)>;
// Optional probe for a PDU this server already stored (any status) in `room_id` (ADR-0285). The
// transaction handler asks it before verifying a PDU's signatures, so a re-sent PDU costs no key lookup,
// and answers a hit as handled without invoking pdu_sink. Unset means every PDU goes on to the sink,
// which still answers PduIngestionStatus::already_stored for a stored event.
using PduStoredProbe = std::function<bool(std::string_view room_id, std::string_view event_id)>;

} // namespace merovingian::federation
