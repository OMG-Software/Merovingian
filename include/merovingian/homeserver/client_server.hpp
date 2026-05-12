// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <merovingian/homeserver/vertical_slice.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

struct ClientDevice final
{
    std::string user_id{};
    std::string device_id{};
    std::string display_name{};
};

struct ClientRateLimitCounter final
{
    std::string bucket{};
    std::uint32_t count{0U};
    std::uint64_t window_start_request{0U};
};

struct ClientApiLimits final
{
    std::size_t max_body_bytes{4096U};
    std::uint32_t max_requests_per_bucket{64U};
    std::uint64_t rate_limit_window_requests{64U};
    std::size_t max_sync_rooms{16U};
    std::size_t max_sync_events_per_room{8U};
};

struct ClientServerRuntime final
{
    HomeserverRuntime homeserver{};
    ClientApiLimits limits{};
    std::vector<ClientDevice> devices{};
    std::vector<ClientRateLimitCounter> rate_limits{};
    std::uint64_t request_clock{0U};
};

struct ClientServerStartResult final
{
    bool started{false};
    std::string reason{};
    ClientServerRuntime runtime{};
};

[[nodiscard]] auto start_client_server(config::Config const& config) -> ClientServerStartResult;
[[nodiscard]] auto matrix_error(std::string_view errcode, std::string_view message) -> std::string;
[[nodiscard]] auto is_matrix_error_response(LocalHttpResponse const& response) noexcept -> bool;
[[nodiscard]] auto handle_client_server_request(ClientServerRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto handle_client_server_http_request(ClientServerRuntime& runtime, std::string_view raw_request)
    -> LocalHttpResponse;
[[nodiscard]] auto device_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept -> std::size_t;
[[nodiscard]] auto joined_room_count(ClientServerRuntime const& runtime, std::string_view user_id) noexcept
    -> std::size_t;
[[nodiscard]] auto run_client_server_flow(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
