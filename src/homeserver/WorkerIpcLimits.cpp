// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/WorkerIpcLimits.hpp"

#include "merovingian/ipc/IpcChannel.hpp"

#include <algorithm>

namespace merovingian::homeserver
{

auto worker_ipc_frame_bytes(config::Config const& config) -> std::uint32_t
{
    // Request bodies cross as JSON strings and may expand more than response bodies, which use
    // fixed base64 encoding (ADR-0043).
    auto const join_response_max_size = config::parse_size_limit(config.security().federation.join_response_max_size);
    auto const backfill_response_max_size =
        config::parse_size_limit(config.security().federation.backfill.response_max_size);
    auto const federation_request_body_size =
        config::parse_size_limit(config.security().federation.max_transaction_size);
    auto const http_body_size = config::parse_size_limit(config.server().http.max_body_size);
    auto const client_api_body_size = config::parse_size_limit(config.server().client_api.max_body_size);
    auto const& http_config = config.server().http;
    return ipc::frame_bytes_for_transport_caps(
        std::max(join_response_max_size.valid ? join_response_max_size.bytes : 0U,
                 backfill_response_max_size.valid ? backfill_response_max_size.bytes : 0U),
        federation_request_body_size.valid ? federation_request_body_size.bytes : 0U,
        std::max(http_body_size.valid ? http_body_size.bytes : 0U,
                 client_api_body_size.valid ? client_api_body_size.bytes : 0U),
        http_config.max_header_bytes, http_config.max_start_line_bytes);
}

} // namespace merovingian::homeserver
