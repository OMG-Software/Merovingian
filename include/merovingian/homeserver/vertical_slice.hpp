// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/media/repository.hpp"
#include "merovingian/net/listener.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

struct LocalUser final
{
    std::string user_id{};
    std::string password_hash{};
    bool locked{false};
    bool suspended{false};
    bool admin{false};
};

struct LocalSession final
{
    std::string user_id{};
    std::string device_id{};
    std::string access_token_hash{};
    bool revoked{false};
};

struct LocalRoom final
{
    std::string room_id{};
    std::string creator_user_id{};
    std::vector<std::string> members{};
    std::vector<std::string> events{};
};

struct LocalDatabase final
{
    bool opened{false};
    bool schema_validated{false};
    std::uint32_t schema_version{0U};
    std::uint64_t next_session_id{1U};
    std::uint64_t next_event_id{1U};
    std::vector<std::string> tables{};
    std::vector<LocalUser> users{};
    std::vector<LocalSession> sessions{};
    std::vector<LocalRoom> rooms{};
    std::vector<observability::AuditLogEvent> audit_events{};
    database::PersistentStore persistent_store{};
    std::vector<unsigned char> signing_secret_key{};
    std::uint64_t next_stream_ordering{1U};
};

struct HomeserverRuntime final
{
    config::Config config{};
    net::RuntimeListeners listeners{};
    LocalDatabase database{};
    federation::FederationRuntimeState federation{};
    media::LocalMediaRepository media_repository{};
    platform::HardeningSelfCheck hardening{};
    bool started{false};
    // Owned here. Federation callback lambdas capture raw pointers into these,
    // which is safe because the runtime outlives every callback invocation.
    std::unique_ptr<http::OutboundClient> outbound_client{};
    std::unique_ptr<federation::ServerDiscoveryNetwork> discovery_network{};
};

struct RuntimeStartResult final
{
    bool started{false};
    std::string reason{};
    HomeserverRuntime runtime{};
};

struct OperationResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string value{};
    std::string reason{};
};

struct SessionRefreshResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string access_token{};
    std::string refresh_token{};
    std::string user_id{};
    std::string device_id{};
    std::string reason{};
};

struct LocalHttpRequest final
{
    std::string method{};
    std::string target{};
    std::string access_token{};
    std::string body{};
};

struct LocalHttpResponse final
{
    std::uint16_t status{500U};
    std::string body{};
};

[[nodiscard]] auto bootstrap_local_database(config::Config const& config) -> LocalDatabase;
[[nodiscard]] auto bootstrap_local_database(config::Config const& config, database::SchemaState existing_state)
    -> LocalDatabase;
[[nodiscard]] auto database_has_table(LocalDatabase const& database, std::string_view table_name) noexcept -> bool;
[[nodiscard]] auto start_runtime(config::Config const& config) -> RuntimeStartResult;
[[nodiscard]] auto start_runtime(config::Config const& config, database::SchemaState existing_state)
    -> RuntimeStartResult;
[[nodiscard]] auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot;
[[nodiscard]] auto admin_health_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_metrics_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto admin_audit_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto handle_federation_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto register_local_user(HomeserverRuntime& runtime, std::string_view localpart,
                                       std::string_view password, std::string_view registration_token = {})
    -> OperationResult;
[[nodiscard]] auto bootstrap_admin_user(HomeserverRuntime& runtime, std::string_view localpart,
                                        std::string_view password) -> OperationResult;
[[nodiscard]] auto login_local_user(HomeserverRuntime& runtime, std::string_view user_id, std::string_view password,
                                    std::string_view device_id) -> OperationResult;
[[nodiscard]] auto issue_refresh_token_for_session(HomeserverRuntime& runtime, std::string_view user_id,
                                                   std::string_view device_id) -> OperationResult;
[[nodiscard]] auto refresh_local_session(HomeserverRuntime& runtime, std::string_view refresh_token)
    -> SessionRefreshResult;
[[nodiscard]] auto authenticated_user(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>;
// Returns the active session for a presented access token, including the
// device id that was bound at login time. Used by surfaces that scope
// per-device state (e.g. /sync's to_device, OTK counts, fallback keys)
// so the response is keyed on the actual authenticating session rather
// than the first device registered for the user.
[[nodiscard]] auto authenticated_session(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<LocalSession>;
[[nodiscard]] auto authenticated_admin_user(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>;
[[nodiscard]] auto logout_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto logout_all_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto delete_local_device(HomeserverRuntime& runtime, std::string_view user_id, std::string_view device_id)
    -> OperationResult;
[[nodiscard]] auto change_local_user_password(HomeserverRuntime& runtime, std::string_view access_token,
                                              std::string_view new_password) -> OperationResult;
[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto join_room(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id)
    -> OperationResult;
[[nodiscard]] auto ensure_runtime_server_signing_key(HomeserverRuntime& runtime)
    -> std::optional<database::PersistentServerSigningKey>;
[[nodiscard]] auto publish_server_signing_keys(HomeserverRuntime& runtime) -> OperationResult;
[[nodiscard]] auto send_event(HomeserverRuntime& runtime, std::string_view access_token, std::string_view room_id,
                              std::string_view event_json) -> OperationResult;
[[nodiscard]] auto fetch_room_state(HomeserverRuntime const& runtime, std::string_view access_token,
                                    std::string_view room_id) -> OperationResult;
[[nodiscard]] auto upload_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                      std::string_view declared_mime_type, std::string_view sniffed_mime_type,
                                      bool scanner_clean, std::string_view bytes) -> OperationResult;
[[nodiscard]] auto download_local_media(HomeserverRuntime& runtime, std::string_view server_name,
                                        std::string_view media_id) -> OperationResult;
[[nodiscard]] auto admin_quarantine_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                                std::string_view media_id, std::string_view reason) -> OperationResult;
[[nodiscard]] auto admin_release_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                             std::string_view media_id) -> OperationResult;
[[nodiscard]] auto admin_remove_local_media(HomeserverRuntime& runtime, std::string_view access_token,
                                            std::string_view media_id, std::string_view reason) -> OperationResult;
[[nodiscard]] auto remote_media_fetch_disabled(HomeserverRuntime& runtime, std::string_view origin_server,
                                               std::string_view media_id) -> OperationResult;
[[nodiscard]] auto media_metrics_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t;
[[nodiscard]] auto run_local_vertical_slice(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
