// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/homeserver/vertical_slice.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

struct MvpDevice final
{
    std::string user_id{};
    std::string device_id{};
    std::string display_name{};
};

struct MvpRateLimitCounter final
{
    std::string bucket{};
    std::uint32_t count{0U};
};

struct MvpApiLimits final
{
    std::size_t max_body_bytes{4096U};
    std::uint32_t max_requests_per_bucket{64U};
    std::size_t max_sync_rooms{16U};
    std::size_t max_sync_events_per_room{8U};
};

struct ClientServerMvpRuntime final
{
    HomeserverRuntime homeserver{};
    MvpApiLimits limits{};
    std::vector<MvpDevice> devices{};
    std::vector<MvpRateLimitCounter> rate_limits{};
};

struct ClientServerMvpStartResult final
{
    bool started{false};
    std::string reason{};
    ClientServerMvpRuntime runtime{};
};

[[nodiscard]] auto start_client_server_mvp(config::Config const& config) -> ClientServerMvpStartResult;
[[nodiscard]] auto matrix_error(std::string_view errcode, std::string_view message) -> std::string;
[[nodiscard]] auto is_matrix_error_response(LocalHttpResponse const& response) noexcept -> bool;
[[nodiscard]] auto handle_client_server_request(ClientServerMvpRuntime& runtime, LocalHttpRequest const& request)
    -> LocalHttpResponse;
[[nodiscard]] auto device_count(ClientServerMvpRuntime const& runtime, std::string_view user_id) noexcept -> std::size_t;
[[nodiscard]] auto joined_room_count(ClientServerMvpRuntime const& runtime, std::string_view user_id) noexcept -> std::size_t;
[[nodiscard]] auto run_client_server_mvp_flow(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
