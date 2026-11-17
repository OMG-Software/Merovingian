// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// `perform_livekit_request` (ADR-0830): the host lookup and the exchange draw from one deadline, so a slow lookup
// cannot add a whole second budget to a LiveKit call.

#include "merovingian/federation/CachedServerDiscovery.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/homeserver/LiveKitRoomService.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/http/OutboundRequest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace
{

// Answers every address lookup with a loopback address, after `delay`.
class SlowDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    explicit SlowDiscoveryNetwork(std::chrono::milliseconds const delay)
        : delay_{delay}
    {
    }

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        ++lookups_;
        std::this_thread::sleep_for(delay_);
        return {true, {"127.0.0.1"}, {}};
    }

    [[nodiscard]] auto lookups() const noexcept -> int
    {
        return lookups_;
    }

private:
    std::chrono::milliseconds delay_;
    int lookups_{0};
};

[[nodiscard]] auto livekit_request() -> merovingian::http::OutboundRequest
{
    auto request = merovingian::http::OutboundRequest{};
    request.method = "POST";
    request.url = "http://livekit.test:7880/twirp/livekit.RoomService/CreateRoom";
    request.allow_cleartext_http = true;
    return request;
}

} // namespace

SCENARIO("A LiveKit call's host lookup draws from the call's one deadline", "[homeserver][livekit][deadline]")
{
    auto client = merovingian::http::OutboundClient{};
    auto const no_test_perform = merovingian::homeserver::LiveKitTestPerform{};

    GIVEN("a lookup that takes longer than the whole one-second budget")
    {
        auto network = SlowDiscoveryNetwork{std::chrono::milliseconds{1100}};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};

        WHEN("the request is performed")
        {
            auto const result = merovingian::homeserver::perform_livekit_request(livekit_request(), client, discovery,
                                                                                 1U, no_test_perform);

            THEN("it ends as a timeout after the lookup, and no exchange is started")
            {
                CHECK(network.lookups() == 1);
                CHECK_FALSE(result.ok);
                CHECK(result.error == merovingian::http::OutboundError::timeout);
                CHECK(result.error_detail == "deadline exceeded while resolving the LiveKit API host");
            }
        }
    }

    GIVEN("a budget already spent")
    {
        auto network = SlowDiscoveryNetwork{std::chrono::milliseconds{0}};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};

        WHEN("the request is performed with no seconds left")
        {
            auto const result = merovingian::homeserver::perform_livekit_request(livekit_request(), client, discovery,
                                                                                 0U, no_test_perform);

            THEN("it is a timeout and the host is not even looked up")
            {
                CHECK(network.lookups() == 0);
                CHECK_FALSE(result.ok);
                CHECK(result.error == merovingian::http::OutboundError::timeout);
            }
        }
    }
}
