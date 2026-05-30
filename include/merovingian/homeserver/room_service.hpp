// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

struct CreateRoomOptions final
{
    std::string room_version{"12"};
    canonicaljson::Object creation_content{};
    canonicaljson::Object power_level_content_override{};
    std::vector<canonicaljson::Value> initial_state{};
    std::vector<std::string> trusted_invitees{};
    std::string preset{"private_chat"};
    std::string name{};
    std::string topic{};
    std::string room_alias_name{};
    std::vector<std::string> invitees{};
    bool is_direct{false};
};

struct ValidatedMakeJoinResponse final
{
    bool ok{false};
    std::string reason{};
    std::string room_version{};
    canonicaljson::Object event{};
};

[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token,
                               CreateRoomOptions const& options) -> OperationResult;
// Joins a room. `via_servers` are candidate resident servers (from the join
// endpoint's `server_name`/`via` query parameters) to attempt federation
// make_join/send_join against. They are required to join a remote room version 12
// room, whose room ID is a bare reference hash with no `:server` suffix (MSC4291)
// and therefore cannot be routed from the room ID alone.
[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                             std::vector<std::string> const& via_servers = {}) -> OperationResult;
// Parses the `server_name=` and `via=` query parameters (each may repeat) from a
// raw query string into an ordered, de-duplicated list of server names. Values are
// percent-decoded. `server_name` is the legacy spelling; `via` (MSC4156) is current.
[[nodiscard]] auto parse_join_via_servers(std::string_view query) -> std::vector<std::string>;
// Builds the ordered list of candidate resident servers to attempt make_join /
// send_join against: the via servers first (in request order), then the room ID's
// server domain when present (room versions < 12). Room version 12 IDs are bare
// hashes with no domain, so the via servers are the only route. Our own server and
// duplicates are removed.
[[nodiscard]] auto join_candidate_servers(std::vector<std::string> const& via_servers, std::string_view room_id,
                                          std::string_view our_server) -> std::vector<std::string>;
[[nodiscard]] auto validate_make_join_response(std::string_view requested_room_id, std::string_view requested_user_id,
                                               std::string_view body) -> ValidatedMakeJoinResponse;
// Synchronous outbound federation call — signs, discovers, and executes a
// single transaction. Returns {true, body} on HTTP 2xx, {false, reason} otherwise.
// Used by both room_service and client_server for blocking federation requests.
[[nodiscard]] auto perform_sync_outbound_call(http::OutboundClient* outbound_client,
                                              federation::ServerDiscoveryNetwork* discovery_network,
                                              federation::OutboundTransaction const& transaction,
                                              std::string_view key_id, std::string_view secret_key,
                                              std::string_view diagnostic_event)
    -> std::pair<bool, std::string>;

[[nodiscard]] auto ensure_runtime_server_signing_key(HomeserverRuntime& runtime)
    -> std::optional<database::PersistentServerSigningKey>;
[[nodiscard]] auto publish_server_signing_keys(HomeserverRuntime& runtime) -> OperationResult;
[[nodiscard]] auto send_event(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view event_json) -> OperationResult;
[[nodiscard]] auto fetch_room_state(HomeserverRuntime const& runtime, std::string_view access_token,
                                    std::string_view room_id) -> OperationResult;
[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t;

} // namespace merovingian::homeserver
