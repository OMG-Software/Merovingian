// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/config/config.hpp>
#include <merovingian/database/persistent_store.hpp>
#include <merovingian/net/listener.hpp>
#include <merovingian/observability/observability.hpp>
#include <merovingian/platform/hardening_self_check.hpp>

#include <cstdint>
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
    std::vector<std::string> tables{};
    std::vector<LocalUser> users{};
    std::vector<LocalSession> sessions{};
    std::vector<LocalRoom> rooms{};
    std::vector<observability::AuditLogEvent> audit_events{};
    database::PersistentStore persistent_store{};
};

struct HomeserverRuntime final
{
    config::Config config{};
    net::RuntimeListeners listeners{};
    LocalDatabase database{};
    platform::HardeningSelfCheck hardening{};
    bool started{false};
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
    std::string value{};
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
[[nodiscard]] auto bootstrap_local_database(config::Config const& config, database::SchemaState existing_state) -> LocalDatabase;
[[nodiscard]] auto database_has_table(LocalDatabase const& database, std::string_view table_name) noexcept -> bool;
[[nodiscard]] auto start_runtime(config::Config const& config) -> RuntimeStartResult;
[[nodiscard]] auto start_runtime(config::Config const& config, database::SchemaState existing_state) -> RuntimeStartResult;
[[nodiscard]] auto admin_health(HomeserverRuntime const& runtime) -> observability::HealthCheckSnapshot;
[[nodiscard]] auto admin_health_summary(HomeserverRuntime const& runtime) -> std::string;
[[nodiscard]] auto handle_local_http_request(HomeserverRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto register_local_user(
    HomeserverRuntime& runtime,
    std::string_view localpart,
    std::string_view password
) -> OperationResult;
[[nodiscard]] auto login_local_user(
    HomeserverRuntime& runtime,
    std::string_view user_id,
    std::string_view password,
    std::string_view device_id
) -> OperationResult;
[[nodiscard]] auto authenticated_user(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>;
[[nodiscard]] auto logout_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto create_room(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto join_room(
    HomeserverRuntime& runtime,
    std::string_view access_token,
    std::string_view room_id
) -> OperationResult;
[[nodiscard]] auto send_event(
    HomeserverRuntime& runtime,
    std::string_view access_token,
    std::string_view room_id,
    std::string_view event_json
) -> OperationResult;
[[nodiscard]] auto fetch_room_state(
    HomeserverRuntime const& runtime,
    std::string_view access_token,
    std::string_view room_id
) -> OperationResult;
[[nodiscard]] auto audit_event_count(HomeserverRuntime const& runtime) noexcept -> std::size_t;
[[nodiscard]] auto run_local_vertical_slice(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
