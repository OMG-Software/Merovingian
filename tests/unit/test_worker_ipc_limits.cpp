// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for homeserver::worker_ipc_frame_bytes (ADR-0043): main and the federation worker size their
// ends of the IPC channel with this one function, so it must be deterministic and follow the budgets.

#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/WorkerIpcLimits.hpp"
#include "merovingian/ipc/IpcChannel.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <utility>

namespace
{

[[nodiscard]] auto config_with(merovingian::config::ServerConfig server, merovingian::config::SecurityConfig security)
    -> merovingian::config::Config
{
    return merovingian::config::Config{
        std::move(server),   merovingian::config::ListenersConfig{},        merovingian::config::DatabaseConfig{},
        std::move(security), merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

SCENARIO("The worker IPC frame cap follows the configured budgets", "[homeserver][ipc][unit]")
{
    GIVEN("the default configuration")
    {
        auto const config = config_with({}, {});

        WHEN("the frame cap is derived twice")
        {
            auto const first = merovingian::homeserver::worker_ipc_frame_bytes(config);
            auto const second = merovingian::homeserver::worker_ipc_frame_bytes(config);

            THEN("both ends of the channel agree, and the cap is never below the channel's floor")
            {
                REQUIRE(first == second);
                REQUIRE(first >= merovingian::ipc::kIpcMaxFrameBytes);
            }
        }

        WHEN("the cap is compared with the transport caps it is built from")
        {
            auto const expected = merovingian::ipc::frame_bytes_for_transport_caps(
                64ULL * 1024ULL * 1024ULL, 20ULL * 1024ULL * 1024ULL, 1ULL * 1024ULL * 1024ULL, 32768U, 8192U);

            THEN("the derived value is exactly that")
            {
                REQUIRE(merovingian::homeserver::worker_ipc_frame_bytes(config) == expected);
            }
        }
    }

    GIVEN("a configuration with a much larger join response budget")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.join_response_max_size = "512MiB";
        auto const small = config_with({}, {});
        auto const large = config_with({}, security);

        WHEN("the frame caps are derived")
        {
            THEN("the larger budget never lowers the cap")
            {
                REQUIRE(merovingian::homeserver::worker_ipc_frame_bytes(large) >=
                        merovingian::homeserver::worker_ipc_frame_bytes(small));
            }
        }
    }

    GIVEN("a configuration whose size limits do not parse")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.join_response_max_size = "not a size";
        security.federation.max_transaction_size = "";
        auto server = merovingian::config::ServerConfig{};
        server.http.max_body_size = "12 parsecs";

        WHEN("the frame cap is derived")
        {
            auto const bytes = merovingian::homeserver::worker_ipc_frame_bytes(config_with(server, security));

            THEN("the unparsable budgets count as zero and the cap stays at the channel floor or above")
            {
                REQUIRE(bytes >= merovingian::ipc::kIpcMaxFrameBytes);
            }
        }
    }
}
