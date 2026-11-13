// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/federation/MembershipEventTemplate.hpp"
#include "merovingian/federation/PublicRoomsRequest.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/ipc/MembershipTemplateIngest.hpp"
#include "merovingian/ipc/RoomListPage.hpp"
#include "merovingian/ipc/RoomSnapshotPage.hpp"
#include "merovingian/ipc/RoomSnapshotPageRequest.hpp"
#include "merovingian/ipc/RoomSnapshotPagination.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::ipc
{

// JSON escaping helper used by both sides of the federation worker IPC channel.
[[nodiscard]] auto ipc_json_str(std::string_view s) -> std::string;

// JSON string extractor used by both sides of the federation worker IPC channel.
// Assumes the value is a simple string with common JSON escapes.
[[nodiscard]] auto ipc_json_get_str(std::string_view json, std::string_view key) -> std::string;

// JSON integer extractor used by both sides of the federation worker IPC channel.
// Returns 0 when the key is missing or not a JSON number.
[[nodiscard]] auto ipc_json_get_u64(std::string_view json, std::string_view key) -> std::uint64_t;

// Serializes a LocalHttpRequest into the JSON body of a fed_request IPC frame.
[[nodiscard]] auto serialize_fed_request(homeserver::LocalHttpRequest const& request) -> std::string;

// Deserializes the JSON body of a fed_request IPC frame into a LocalHttpRequest.
[[nodiscard]] auto deserialize_fed_request(std::string_view json) -> homeserver::LocalHttpRequest;

// Serializes a LocalHttpResponse into the JSON body of a fed_response IPC frame.
[[nodiscard]] auto serialize_fed_response(homeserver::LocalHttpResponse const& response) -> std::string;

// Deserializes the JSON body of a fed_response IPC frame into a LocalHttpResponse.
[[nodiscard]] auto deserialize_fed_response(std::string_view json) -> homeserver::LocalHttpResponse;

// Serializes a pre-signed OutboundRequest into the JSON body of an
// outbound_http_request IPC frame. The request must already carry the
// X-Matrix Authorization header; the secret key is never sent over IPC.
[[nodiscard]] auto serialize_outbound_http_request(http::OutboundRequest const& request) -> std::string;

// Deserializes the JSON body of an outbound_http_request IPC frame.
[[nodiscard]] auto deserialize_outbound_http_request(std::string_view json) -> http::OutboundRequest;

// Serializes an OutboundResult into the JSON body of an outbound_http_response IPC frame.
[[nodiscard]] auto serialize_outbound_http_response(http::OutboundResult const& result) -> std::string;

// Deserializes the JSON body of an outbound_http_response IPC frame.
[[nodiscard]] auto deserialize_outbound_http_response(std::string_view json) -> http::OutboundResult;

// Serializes a room_sync notification: fire-and-forget, main process to
// worker, telling the worker's otherwise-static PersistentStore snapshot to
// re-read this one room from the database. See
// database::reload_room and docs/architecture.md, "Federation worker room
// staleness".
[[nodiscard]] auto serialize_room_sync_notification(std::string_view room_id, std::uint64_t generation) -> std::string;

// Serializes a room_sync_result notification: fire-and-forget, worker to main,
// reporting whether the worker's reload of the requested room succeeded.
// `state` is "ok" or "failed"; `generation` echoes the value from the incoming
// room_sync notification so main can correlate the asynchronous result.
[[nodiscard]] auto serialize_room_sync_result(std::string_view room_id, std::string_view state,
                                              std::uint64_t generation) -> std::string;

[[nodiscard]] auto serialize_membership_template_ingest(MembershipTemplateIngest const& request) -> std::string;
// std::nullopt for a frame that does not parse or lacks room_id / user_id.
[[nodiscard]] auto deserialize_membership_template_ingest(std::string_view json)
    -> std::optional<MembershipTemplateIngest>;

// Main's answer: the template, or none (404 to the requesting server).
[[nodiscard]] auto serialize_membership_template_ingest_result(
    std::optional<federation::MembershipEventTemplate> const& result) -> std::string;
[[nodiscard]] auto deserialize_membership_template_ingest_result(std::string_view json)
    -> std::optional<federation::MembershipEventTemplate>;

// An inbound publicRooms request a federation worker hands to main (ADR-0461). Worker to main.
[[nodiscard]] auto serialize_public_rooms_ingest(federation::PublicRoomsRequest const& request) -> std::string;
// std::nullopt for a frame that does not parse or holds a request a remote server's could not be: main reads
// the worker's frame with the checks the worker applied to the remote server.
[[nodiscard]] auto deserialize_public_rooms_ingest(std::string_view json)
    -> std::optional<federation::PublicRoomsRequest>;

// Main's answer: the 200 response body, or none (503 to the requesting server).
[[nodiscard]] auto serialize_public_rooms_ingest_result(std::optional<std::string> const& body) -> std::string;
// std::nullopt for a refusal, or a frame such as main's overload answer that holds no listing.
[[nodiscard]] auto deserialize_public_rooms_ingest_result(std::string_view json) -> std::optional<std::string>;

// ---- The federation worker's store, from main (C44, ADR-0733) ----
//
// The worker opens no database. At start it asks main for the room list, page by page, then for each listed room's
// snapshot, page by page; after a room_sync it asks for that room's snapshot again; and a key lookup asks main for a
// server's public signing keys. Every string a row holds goes through the lossless form (`<key>_b64` for bytes that
// are not UTF-8, ADR-0321) and every integer as decimal text, so a row arrives exactly whatever it holds and no
// integer meets the parser's 2^53 limit.

// What a page body may hold: the frame cap less room for the frame header (`id`, `reply_to`). 0 when the cap is
// smaller than the header room.
[[nodiscard]] auto worker_store_page_budget(std::size_t max_frame_bytes) noexcept -> std::size_t;

// Worker to main: page `page` of the room list.
[[nodiscard]] auto serialize_room_list_request(std::uint64_t page) -> std::string;
// std::nullopt for a frame that does not parse or holds no page number.
[[nodiscard]] auto deserialize_room_list_request(std::string_view json) -> std::optional<std::uint64_t>;
// Main: `room_ids` cut into room_list_page bodies of at most `page_budget` bytes each, in order; one page for no
// rooms. Empty when an ID does not fit a page on its own.
[[nodiscard]] auto paginate_room_list(std::vector<std::string> const& room_ids, std::size_t page_budget)
    -> std::vector<std::string>;
// std::nullopt for a refusal or a frame that does not parse.
[[nodiscard]] auto deserialize_room_list_page(std::string_view json) -> std::optional<RoomListPage>;

// Worker to main: one page of a room snapshot.
[[nodiscard]] auto serialize_room_snapshot_request(RoomSnapshotPageRequest const& request) -> std::string;
// std::nullopt for a frame that does not parse, or a room ID that is empty or over 255 bytes.
[[nodiscard]] auto deserialize_room_snapshot_request(std::string_view json) -> std::optional<RoomSnapshotPageRequest>;
// Main: `snapshot` cut into room_snapshot_page bodies of at most `page_budget` bytes each, rows packed in order and
// the room row on page 0. A room with no rows is one page. A row that does not fit a page on its own, or a snapshot
// with nothing to apply, gives no pages and a refusal; nothing is ever cut short.
[[nodiscard]] auto paginate_room_snapshot(database::RoomReloadSnapshot const& snapshot, std::uint64_t generation,
                                          std::size_t page_budget) -> RoomSnapshotPagination;
// Main's answer when it will not or cannot send a page: names the reason, carries no rows.
[[nodiscard]] auto serialize_worker_store_refusal(std::string_view type, std::string_view reason) -> std::string;
// std::nullopt for a refusal, a frame that does not parse, or any row that does not.
[[nodiscard]] auto deserialize_room_snapshot_page(std::string_view json) -> std::optional<RoomSnapshotPage>;

// Worker to main: the public signing keys main holds for `server_name`.
[[nodiscard]] auto serialize_server_keys_request(std::string_view server_name) -> std::string;
// std::nullopt for a frame that does not parse, or a server name that is empty or over 255 bytes.
[[nodiscard]] auto deserialize_server_keys_request(std::string_view json) -> std::optional<std::string>;
// Main's answer: public columns only (a secret is never written, whatever the row holds).
[[nodiscard]] auto serialize_server_keys_result(std::vector<database::PersistentServerSigningKey> const& keys)
    -> std::string;
// std::nullopt for a refusal or a frame that does not parse; an empty list is a real answer.
[[nodiscard]] auto deserialize_server_keys_result(std::string_view json)
    -> std::optional<std::vector<database::PersistentServerSigningKey>>;

} // namespace merovingian::ipc
