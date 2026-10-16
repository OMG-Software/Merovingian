// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "joining_threads.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ipc_auth_key.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/ipc/channel.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <exception>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <sodium.h>
#include <sys/socket.h>
#include <sys/time.h>

namespace merovingian::tests
{

// Shared by the downstream integration and sync fixtures. Unlike a fabricated
// authorization callback, this fixture uses the real authenticated transport and
// main-owned pending metadata. Signature verification is covered independently
// by the FED-12 behavioral regression, not by this downstream setup helper.
struct EduRelayChannels final
{
    std::unique_ptr<ipc::IpcChannel> main{};
    std::unique_ptr<ipc::IpcChannel> worker{};
};

[[nodiscard]] inline auto make_edu_relay_channels() -> EduRelayChannels
{
    REQUIRE(sodium_init() >= 0);
    auto descriptors = std::array<int, 2>{-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors.data()) == 0);
    auto main_fd = core::FileDescriptor{descriptors[0]};
    auto worker_fd = core::FileDescriptor{descriptors[1]};
    auto const timeout = ::timeval{.tv_sec = 10, .tv_usec = 0};
    for (auto const descriptor : descriptors)
    {
        REQUIRE(::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        REQUIRE(::setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    }
    auto material = core::SecretBuffer{32U};
    randombytes_buf(material.bytes().data(), material.bytes().size());
    auto const authentication = crypto::derive_ipc_auth_key(material.bytes());
    REQUIRE(authentication.has_value());
    auto channels = EduRelayChannels{};
    auto main_error = std::exception_ptr{};
    auto worker_error = std::exception_ptr{};
    auto constructors = JoiningThreads{};
    constructors.emplace_back([&] {
        try
        {
            channels.main =
                std::make_unique<ipc::IpcChannel>(std::move(main_fd), ipc::IpcChannel::Role::server, *authentication);
        }
        catch (...)
        {
            main_error = std::current_exception();
        }
    });
    constructors.emplace_back([&] {
        try
        {
            channels.worker =
                std::make_unique<ipc::IpcChannel>(std::move(worker_fd), ipc::IpcChannel::Role::client, *authentication);
        }
        catch (...)
        {
            worker_error = std::current_exception();
        }
    });
    constructors.join();
    REQUIRE(!main_error);
    REQUIRE(!worker_error);
    return channels;
}

// Install the main request handler before construction when testing an EDU RPC
// round trip. This context borrows the pair and owns its started lifetime; it
// releases the actual worker reply and consumes the main future before stopping
// both channels, including assertion/exception unwinding. Construct and destroy
// outside runtime locks. No wait or channel write holds the fixture mutex.
class EduRelayContext final
{
public:
    EduRelayContext(ipc::IpcChannel& main_channel, ipc::IpcChannel& worker_channel)
        : main_(main_channel)
        , worker_(worker_channel)
    {
        worker_.set_request_handler([this](std::uint64_t id, std::string) {
            auto release = false;
            {
                auto guard = std::lock_guard{mutex_};
                parent_id_ = id;
                release = releasing_;
            }
            received_.notify_all();
            if (release)
                worker_.send_response(id, completion_);
        });
        try
        {
            main_.start();
            worker_.start();
        }
        catch (...)
        {
            main_.stop();
            worker_.stop();
            throw;
        }
    }
    EduRelayContext(EduRelayContext const&) = delete;
    auto operator=(EduRelayContext const&) -> EduRelayContext& = delete;
    ~EduRelayContext() noexcept
    {
        std::ignore = finish();
        main_.stop();
        worker_.stop();
    }

    // trusted_origin is explicitly selected by the testcase, never extracted
    // from the worker's EDU frame (whose claimed origin may be invalid).
    [[nodiscard]] auto establish(std::string_view trusted_origin) -> bool
    {
        REQUIRE(!pending_.valid());
        auto request = homeserver::LocalHttpRequest{};
        request.method = "PUT";
        request.target = "/_matrix/federation/v1/send/test-relay-context";
        request.body = "{}";
        request.verified_origin = trusted_origin;
        auto frame = ipc::serialize_fed_request(request);
        pending_ =
            std::async(std::launch::async, [this, frame = std::move(frame), origin = std::string{trusted_origin}] {
                return main_.send_request(frame, std::chrono::seconds{30}, origin);
            });
        auto guard = std::unique_lock{mutex_};
        if (!received_.wait_for(guard, std::chrono::seconds{10}, [this] {
                return parent_id_ != 0U;
            }))
            return false;
        auto const id = parent_id_;
        guard.unlock();
        return main_.matches_pending_origin(id, trusted_origin);
    }

    [[nodiscard]] auto wrap(std::string_view relay_json) const -> std::string
    {
        REQUIRE(!relay_json.empty());
        REQUIRE(relay_json.front() == '{');
        auto guard = std::lock_guard{mutex_};
        REQUIRE(parent_id_ != 0U);
        return "{\"parent_request_id\":" + std::to_string(parent_id_) + "," + std::string{relay_json.substr(1U)};
    }

    [[nodiscard]] auto finish() noexcept -> bool
    {
        if (finished_)
            return completion_ok_;
        try
        {
            auto id = std::uint64_t{};
            {
                auto guard = std::lock_guard{mutex_};
                releasing_ = true;
                id = parent_id_;
            }
            if (id != 0U)
                worker_.send_response(id, completion_);
            if (pending_.valid())
            {
                if (pending_.wait_for(std::chrono::seconds{5}) != std::future_status::ready)
                {
                    completion_ok_ = false;
                    main_.stop();
                    worker_.stop();
                }
                auto const reply = pending_.get();
                completion_ok_ =
                    completion_ok_ && reply.has_value() && ipc::deserialize_fed_response(*reply).status == 200U;
            }
        }
        catch (...)
        {
            completion_ok_ = false;
            main_.stop();
            worker_.stop();
            if (pending_.valid())
            {
                try
                {
                    std::ignore = pending_.get();
                }
                catch (...)
                {
                }
            }
        }
        finished_ = true;
        return completion_ok_;
    }

private:
    ipc::IpcChannel& main_;
    ipc::IpcChannel& worker_;
    mutable std::mutex mutex_{};
    std::condition_variable received_{};
    std::uint64_t parent_id_{};
    std::future<std::optional<std::string>> pending_{};
    std::string completion_{ipc::serialize_fed_response({200U, "{}"})};
    bool releasing_{false};
    bool finished_{false};
    bool completion_ok_{true};
};

[[nodiscard]] inline auto ingest_edu_with_live_context(homeserver::HomeserverRuntime& runtime,
                                                       std::string_view relay_json, std::string_view trusted_origin)
    -> std::string
{
    auto channels = make_edu_relay_channels();
    auto context = EduRelayContext{*channels.main, *channels.worker};
    REQUIRE(context.establish(trusted_origin));
    auto const response = homeserver::handle_edu_ingest_request(runtime, context.wrap(relay_json), *channels.main);
    REQUIRE(context.finish());
    return response;
}

} // namespace merovingian::tests
