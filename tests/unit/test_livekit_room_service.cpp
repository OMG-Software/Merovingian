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
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

// Answers every address lookup with a loopback address, after `delay`.
class SlowDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    explicit SlowDiscoveryNetwork(std::chrono::milliseconds const delay, bool const answer_ok = true,
                                  std::vector<std::string> addresses = {"127.0.0.1"})
        : delay_{delay}
        , answer_ok_{answer_ok}
        , addresses_{std::move(addresses)}
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
        return {answer_ok_, addresses_, {}};
    }

    [[nodiscard]] auto lookups() const noexcept -> int
    {
        return lookups_;
    }

private:
    std::chrono::milliseconds delay_;
    bool answer_ok_;
    std::vector<std::string> addresses_;
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

SCENARIO("The LiveKit request builders refuse an address, key, secret or name they cannot sign for",
         "[homeserver][livekit][negative]")
{
    GIVEN("a valid https API URL, key, 32-byte secret and MSC4195 names")
    {
        auto const secret = std::vector<std::uint8_t>(32U, 0x07U);
        auto const short_secret = std::vector<std::uint8_t>(31U, 0x07U);
        auto const room = std::string{"O8437W3+jmzMVjoIP3tNwbm+XxHQk2iKpOA7aqw3qSc"};
        auto const identity = std::string{"M3VnsLXrkbxIDINXO64u8PZzFyD9ZYFiQULR2dshWYs"};
        auto const url = std::string{"https://livekit.example:7880"};

        WHEN("the control call and each invalid variation are built")
        {
            using merovingian::homeserver::livekit_create_room_request;
            using merovingian::homeserver::livekit_get_participant_request;

            auto const control_create = livekit_create_room_request(url, "key", secret, room, 1'700'000'000);
            auto const control_get = livekit_get_participant_request(url, "key", secret, room, identity, 1'700'000'000);

            THEN("the controls build, and every variation is refused with no request")
            {
                CHECK(control_create.has_value());
                CHECK(control_get.has_value());

                for (auto const* bad_url : {"http://livekit.example:7880", "http://10.0.0.1:7880", "ftp://127.0.0.1",
                                            "not a url", "", "https://livekit.example:7880/?x=1"})
                {
                    CAPTURE(bad_url);
                    CHECK_FALSE(livekit_create_room_request(bad_url, "key", secret, room, 1'700'000'000));
                    CHECK_FALSE(livekit_get_participant_request(bad_url, "key", secret, room, identity, 1'700'000'000));
                }
                CHECK_FALSE(livekit_create_room_request(url, "key", short_secret, room, 1'700'000'000));
                CHECK_FALSE(
                    livekit_create_room_request(url, "key", std::span<std::uint8_t const>{}, room, 1'700'000'000));
                CHECK_FALSE(livekit_create_room_request(url, "", secret, room, 1'700'000'000));
                CHECK_FALSE(livekit_create_room_request(url, "key", secret, "short", 1'700'000'000));
                CHECK_FALSE(livekit_create_room_request(url, "key", secret, room, -1));
                CHECK_FALSE(livekit_get_participant_request(url, "key", short_secret, room, identity, 1'700'000'000));
                CHECK_FALSE(livekit_get_participant_request(url, "", secret, room, identity, 1'700'000'000));
                CHECK_FALSE(livekit_get_participant_request(url, "key", secret, "short", identity, 1'700'000'000));
                CHECK_FALSE(
                    livekit_get_participant_request(url, "key", secret, room, "@alice:example.com", 1'700'000'000));
                CHECK_FALSE(livekit_get_participant_request(url, "key", secret, room, identity, -1));
            }
        }
    }
}

SCENARIO("A LiveKit call whose URL does not parse or whose host does not resolve fails before any exchange",
         "[homeserver][livekit][negative]")
{
    auto client = merovingian::http::OutboundClient{};
    auto const no_test_perform = merovingian::homeserver::LiveKitTestPerform{};

    GIVEN("a request whose URL is not a URL")
    {
        auto network = SlowDiscoveryNetwork{std::chrono::milliseconds{0}};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};
        auto request = livekit_request();
        request.url = "not a url";

        WHEN("it is performed")
        {
            auto const result =
                merovingian::homeserver::perform_livekit_request(request, client, discovery, 5U, no_test_perform);

            THEN("it is an invalid_url failure and the host is never looked up")
            {
                CHECK_FALSE(result.ok);
                CHECK(result.error == merovingian::http::OutboundError::invalid_url);
                CHECK(result.error_detail == "invalid LiveKit API URL");
                CHECK(network.lookups() == 0);
            }
        }
    }

    GIVEN("a lookup that fails, and one that succeeds with no address")
    {
        auto failing = SlowDiscoveryNetwork{std::chrono::milliseconds{0}, false, {}};
        auto empty = SlowDiscoveryNetwork{std::chrono::milliseconds{0}, true, {}};
        auto failing_discovery = merovingian::federation::CachedServerDiscovery{failing, 60000U, []() -> std::uint64_t {
                                                                                    return 0U;
                                                                                }};
        auto empty_discovery = merovingian::federation::CachedServerDiscovery{empty, 60000U, []() -> std::uint64_t {
                                                                                  return 0U;
                                                                              }};

        WHEN("the request is performed against each")
        {
            auto const failed = merovingian::homeserver::perform_livekit_request(
                livekit_request(), client, failing_discovery, 5U, no_test_perform);
            auto const none = merovingian::homeserver::perform_livekit_request(livekit_request(), client,
                                                                               empty_discovery, 5U, no_test_perform);

            THEN("each is an unresolved_host failure after one lookup, with no exchange")
            {
                CHECK(failing.lookups() == 1);
                CHECK(empty.lookups() == 1);
                CHECK_FALSE(failed.ok);
                CHECK(failed.error == merovingian::http::OutboundError::unresolved_host);
                CHECK(failed.error_detail == "failed to resolve the LiveKit API host");
                CHECK_FALSE(none.ok);
                CHECK(none.error == merovingian::http::OutboundError::unresolved_host);
                CHECK(none.error_detail == "failed to resolve the LiveKit API host");
            }
        }
    }
}
