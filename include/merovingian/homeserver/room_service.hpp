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
[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult;
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
