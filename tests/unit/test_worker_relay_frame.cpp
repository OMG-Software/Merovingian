// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// GHSA-3p5v-vrg8-f545 (ADR-0595): the frame a federation worker sends main for a bound claim or query relay, and the
// send itself. Main's handlers (homeserver/WorkerPool.cpp) read the type, `parent_request_id` and the argument field
// these frames carry; the integration relay scenarios run main against frames built here.

#include "../support/EduRelayContext.hpp"
#include "merovingian/federation/WorkerRelayKind.hpp"
#include "merovingian/federation_worker/worker_relay_frame.hpp"
#include "merovingian/ipc/IpcChannel.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <future>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using merovingian::federation::WorkerRelayKind;
using merovingian::federation_worker::relay_to_main;
using merovingian::federation_worker::worker_relay_frame;

struct ExpectedFrame
{
    WorkerRelayKind kind;
    std::string_view type;
    std::string_view argument_field;
};

// Stops both channels however the scenario ends, so no reader thread outlives a failed assertion.
class StopChannels final
{
public:
    explicit StopChannels(merovingian::tests::EduRelayChannels& channels) noexcept
        : channels_(channels)
    {
    }
    StopChannels(StopChannels const&) = delete;
    auto operator=(StopChannels const&) -> StopChannels& = delete;
    ~StopChannels() noexcept
    {
        channels_.worker->stop();
        channels_.main->stop();
    }

private:
    merovingian::tests::EduRelayChannels& channels_;
};

} // namespace

SCENARIO("a worker's bound relay frame names its kind, its parent request and its argument",
         "[unit][ghsa-3p5v][relay-frame]")
{
    GIVEN("the four relay kinds and an argument holding characters JSON must escape")
    {
        auto const expected = std::array{
            ExpectedFrame{WorkerRelayKind::otk_claim,         "otk_claim_ingest",         "request_body"},
            ExpectedFrame{WorkerRelayKind::device_keys_query, "device_keys_query_ingest", "request_body"},
            ExpectedFrame{WorkerRelayKind::user_devices,      "user_devices_ingest",      "user_id"     },
            ExpectedFrame{WorkerRelayKind::profile_query,     "profile_query_ingest",     "user_id"     },
        };
        auto const argument = std::string{R"({"one_time_keys":{"@a\"b:hs":{"D":"x\\y"}}})"};

        WHEN("each frame is built under parent request 42")
        {
            THEN("main reads back the frame type, the parent and the argument unchanged, under the kind's field")
            {
                for (auto const& frame_shape : expected)
                {
                    auto const frame = worker_relay_frame(frame_shape.kind, argument, 42U);
                    REQUIRE(frame.has_value());
                    INFO("frame: " << *frame);
                    CHECK(merovingian::ipc::ipc_json_get_str(*frame, "type") == frame_shape.type);
                    CHECK(merovingian::ipc::ipc_json_get_u64(*frame, "parent_request_id") == 42U);
                    CHECK(merovingian::ipc::ipc_json_get_str(*frame, frame_shape.argument_field) == argument);
                }
            }
        }
        WHEN("each frame is built with no parent request")
        {
            THEN("there is no frame: a worker serving no forwarded request relays nothing")
            {
                for (auto const& frame_shape : expected)
                {
                    CHECK_FALSE(worker_relay_frame(frame_shape.kind, argument, 0U).has_value());
                }
            }
        }
    }
}

SCENARIO("a worker sends a bound relay to main only under a parent request", "[unit][ghsa-3p5v][relay-frame]")
{
    GIVEN("a worker channel whose main end records the frame it receives and answers it")
    {
        auto channels = merovingian::tests::make_edu_relay_channels();
        auto received_promise = std::promise<std::string>{};
        auto received = received_promise.get_future();
        auto& main_channel = *channels.main;
        main_channel.set_request_handler([&](std::uint64_t id, std::string frame) {
            received_promise.set_value(std::move(frame));
            main_channel.send_response(id, R"({"response_body":"answered"})");
        });
        auto const stop = StopChannels{channels};
        channels.main->start();
        channels.worker->start();

        WHEN("a device-list relay is sent under parent request 7")
        {
            auto const reply = relay_to_main(*channels.worker, WorkerRelayKind::user_devices, "@b:hs.example", 7U,
                                             std::chrono::seconds{10});

            // The channel adds its own request `id` to the frame, so compare what main's handler reads.
            THEN("main receives the worker's relay under parent 7 and the worker gets main's answer")
            {
                REQUIRE(reply.has_value());
                CHECK(merovingian::ipc::ipc_json_get_str(*reply, "response_body") == "answered");
                REQUIRE(received.wait_for(std::chrono::seconds{0}) == std::future_status::ready);
                auto const frame = received.get();
                INFO("frame: " << frame);
                CHECK(merovingian::ipc::ipc_json_get_str(frame, "type") == "user_devices_ingest");
                CHECK(merovingian::ipc::ipc_json_get_u64(frame, "parent_request_id") == 7U);
                CHECK(merovingian::ipc::ipc_json_get_str(frame, "user_id") == "@b:hs.example");
            }
        }
        WHEN("the same relay is attempted with no parent request")
        {
            auto const reply = relay_to_main(*channels.worker, WorkerRelayKind::user_devices, "@b:hs.example", 0U,
                                             std::chrono::seconds{10});

            THEN("nothing is sent and there is no answer")
            {
                CHECK_FALSE(reply.has_value());
                CHECK(received.wait_for(std::chrono::milliseconds{200}) == std::future_status::timeout);
            }
        }
    }
}
