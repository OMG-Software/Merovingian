// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/worker_relay_frame.hpp"

#include "merovingian/federation/WorkerRelayKind.hpp"
#include "merovingian/ipc/IpcChannel.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::federation_worker
{

namespace
{

    struct RelayFrameShape
    {
        std::string_view type;
        std::string_view argument_field;
    };

    // The frame type and argument field main's handler for each kind reads (homeserver/WorkerPool.cpp).
    [[nodiscard]] constexpr auto relay_frame_shape(federation::WorkerRelayKind kind) noexcept -> RelayFrameShape
    {
        switch (kind)
        {
        case federation::WorkerRelayKind::otk_claim:
            return {"otk_claim_ingest", "request_body"};
        case federation::WorkerRelayKind::device_keys_query:
            return {"device_keys_query_ingest", "request_body"};
        case federation::WorkerRelayKind::user_devices:
            return {"user_devices_ingest", "user_id"};
        case federation::WorkerRelayKind::profile_query:
            break;
        }
        return {"profile_query_ingest", "user_id"};
    }

} // namespace

auto worker_relay_frame(federation::WorkerRelayKind kind, std::string_view argument, std::uint64_t parent_request_id)
    -> std::optional<std::string>
{
    if (parent_request_id == 0U)
    {
        return std::nullopt;
    }
    auto const shape = relay_frame_shape(kind);
    auto frame = std::string{R"({"type":)"};
    frame.reserve(96U + argument.size());
    frame += ipc::ipc_json_str(shape.type);
    frame += R"(,"parent_request_id":)";
    frame += std::to_string(parent_request_id);
    frame += ",";
    frame += ipc::ipc_json_str(shape.argument_field);
    frame += ":";
    frame += ipc::ipc_json_str(argument);
    frame += '}';
    return frame;
}

auto relay_to_main(ipc::IpcChannel& channel, federation::WorkerRelayKind kind, std::string_view argument,
                   std::uint64_t parent_request_id, std::chrono::seconds timeout) -> std::optional<std::string>
{
    auto const frame = worker_relay_frame(kind, argument, parent_request_id);
    if (!frame.has_value())
    {
        return std::nullopt;
    }
    return channel.send_request(*frame, timeout);
}

} // namespace merovingian::federation_worker
