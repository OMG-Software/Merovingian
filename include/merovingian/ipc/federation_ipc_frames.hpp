// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <string>
#include <string_view>

namespace merovingian::ipc
{

// JSON escaping helper used by both sides of the federation worker IPC channel.
[[nodiscard]] auto ipc_json_str(std::string_view s) -> std::string;

// JSON string extractor used by both sides of the federation worker IPC channel.
// Assumes the value is a simple string with common JSON escapes.
[[nodiscard]] auto ipc_json_get_str(std::string_view json, std::string_view key) -> std::string;

// Serializes a LocalHttpRequest into the JSON body of a fed_request IPC frame.
[[nodiscard]] auto serialize_fed_request(homeserver::LocalHttpRequest const& request) -> std::string;

// Deserializes the JSON body of a fed_request IPC frame into a LocalHttpRequest.
[[nodiscard]] auto deserialize_fed_request(std::string_view json) -> homeserver::LocalHttpRequest;

// Serializes a LocalHttpResponse into the JSON body of a fed_response IPC frame.
[[nodiscard]] auto serialize_fed_response(homeserver::LocalHttpResponse const& response) -> std::string;

// Deserializes the JSON body of a fed_response IPC frame into a LocalHttpResponse.
[[nodiscard]] auto deserialize_fed_response(std::string_view json) -> homeserver::LocalHttpResponse;

// Serializes a pre-signed OutboundRequest into the JSON body of an
// outbound_http_request IPC frame. The request must already carry the
// X-Matrix Authorization header; the secret key is never sent over IPC.
[[nodiscard]] auto serialize_outbound_http_request(http::OutboundRequest const& request) -> std::string;

// Deserializes the JSON body of an outbound_http_request IPC frame.
[[nodiscard]] auto deserialize_outbound_http_request(std::string_view json) -> http::OutboundRequest;

// Serializes an OutboundResult into the JSON body of an outbound_http_response IPC frame.
[[nodiscard]] auto serialize_outbound_http_response(http::OutboundResult const& result) -> std::string;

// Deserializes the JSON body of an outbound_http_response IPC frame.
[[nodiscard]] auto deserialize_outbound_http_response(std::string_view json) -> http::OutboundResult;

} // namespace merovingian::ipc
