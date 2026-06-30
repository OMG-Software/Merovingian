// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/federation_ipc_frames.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/http/request.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::ipc
{

namespace
{

    // The IPC frames use insertion-order (non-canonical) keys and may carry
    // string values that themselves contain `"headers":[...]`-shaped substrings or
    // escaped quotes. The hand-rolled substring scanners previously used here
    // misparsed those cases (issue #320). Parsing once with the fuzzed,
    // depth-bounded canonicaljson parser and walking the resulting DOM removes
    // that class of bug. parse_json (not parse_lossless) is used because the
    // frames are not canonical (unsorted keys) and need not be signing-safe.

    [[nodiscard]] auto object_of(canonicaljson::Value const& v) -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&v.storage());
    }

    [[nodiscard]] auto find_member(canonicaljson::Object const& obj, std::string_view key)
        -> canonicaljson::Value const*
    {
        for (auto const& member : obj)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto get_str(canonicaljson::Object const& obj, std::string_view key) -> std::string
    {
        auto const* value = find_member(obj, key);
        if (value == nullptr)
        {
            return {};
        }
        auto const* str = std::get_if<std::string>(&value->storage());
        return (str != nullptr) ? *str : std::string{};
    }

    [[nodiscard]] auto get_int(canonicaljson::Object const& obj, std::string_view key) -> std::int64_t
    {
        auto const* value = find_member(obj, key);
        if (value == nullptr)
        {
            return 0;
        }
        auto const* num = std::get_if<std::int64_t>(&value->storage());
        return (num != nullptr) ? *num : 0;
    }

    [[nodiscard]] auto get_bool(canonicaljson::Object const& obj, std::string_view key) -> bool
    {
        auto const* value = find_member(obj, key);
        if (value == nullptr)
        {
            return false;
        }
        auto const* b = std::get_if<bool>(&value->storage());
        return (b != nullptr) ? *b : false;
    }

    [[nodiscard]] auto get_array(canonicaljson::Object const& obj, std::string_view key) -> canonicaljson::Array const*
    {
        auto const* value = find_member(obj, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Array>(&value->storage());
    }

    // Extracts an array of {"n":...,"v":...} header objects into a container of
    // {name, value} pairs. Works for http::Header, OutboundHeader, and
    // std::pair<std::string, std::string> (all two-string aggregate/brace-init).
    template <typename Container>
    auto extract_headers(canonicaljson::Array const& arr, Container& out) -> void
    {
        for (auto const& elem : arr)
        {
            auto const* obj = object_of(elem);
            if (obj == nullptr)
            {
                continue;
            }
            auto name = get_str(*obj, "n");
            auto value = get_str(*obj, "v");
            if (!name.empty())
            {
                out.push_back({std::move(name), std::move(value)});
            }
        }
    }

    // Numeric IPC fields are stored as int64 in the canonicaljson DOM. Clamp
    // into the narrower unsigned destination types, returning 0 for negative
    // or out-of-range values (matching the prior from_chars fallback on
    // malformed input, which left the destination at its zero-initialised value).
    [[nodiscard]] auto clamp_to_u32(std::int64_t v) -> std::uint64_t
    {
        if (v < 0 || v > static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max()))
        {
            return 0U;
        }
        return static_cast<std::uint64_t>(v);
    }

    [[nodiscard]] auto clamp_to_u64(std::int64_t v) -> std::uint64_t
    {
        if (v < 0)
        {
            return 0U;
        }
        return static_cast<std::uint64_t>(v);
    }

    // #323: case-insensitive comparison of a header name against the credential
    // headers that must never cross the IPC boundary. "authorization" covers
    // the X-Matrix federation header (sent as `Authorization: X-Matrix ...`);
    // "x-matrix" is matched explicitly in case a caller splits the scheme.
    [[nodiscard]] auto is_credential_header_name(std::string_view name) -> bool
    {
        auto equals_ci = [](std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size())
            {
                return false;
            }
            for (std::size_t i = 0U; i < a.size(); ++i)
            {
                auto const to_lower = [](unsigned char c) noexcept -> char {
                    return static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
                };
                if (to_lower(static_cast<unsigned char>(a[i])) != to_lower(static_cast<unsigned char>(b[i])))
                {
                    return false;
                }
            }
            return true;
        };
        return equals_ci(name, "authorization") || equals_ci(name, "x-matrix");
    }

} // namespace

auto ipc_json_str(std::string_view s) -> std::string
{
    auto result = std::string{};
    result.reserve(s.size() + 2U);
    result += '"';
    for (auto const raw_ch : s)
    {
        auto const ch = static_cast<unsigned char>(raw_ch);
        switch (ch)
        {
        case '"':
            result += "\\\"";
            break;
        case '\\':
            result += "\\\\";
            break;
        case '\b':
            result += "\\b";
            break;
        case '\f':
            result += "\\f";
            break;
        case '\n':
            result += "\\n";
            break;
        case '\r':
            result += "\\r";
            break;
        case '\t':
            result += "\\t";
            break;
        default:
            if (ch < 0x20U)
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(ch));
                result += buf;
            }
            else
            {
                result += static_cast<char>(ch);
            }
            break;
        }
    }
    result += '"';
    return result;
}

auto ipc_json_get_str(std::string_view json, std::string_view key) -> std::string
{
    // Parse the whole document and read the key from the top-level object.
    // This correctly handles escaped quotes and string values that themselves
    // contain `"key":`-shaped substrings (issue #320) — the substring scanner
    // previously used here misparsed both. On any parse error or a non-string
    // value the empty string is returned, matching the prior fallback shape.
    // The ParseResult must live for the whole function so the Object pointer
    // into its Value remains valid while the field is read.
    auto const parsed = canonicaljson::parse_json(json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return {};
    }
    auto const* obj = object_of(parsed.value);
    if (obj == nullptr)
    {
        return {};
    }
    return get_str(*obj, key);
}

auto serialize_fed_request(homeserver::LocalHttpRequest const& request) -> std::string
{
    auto body = std::string{};
    body.reserve(512U + request.body.size());
    body += R"({"type":"fed_request","method":)";
    body += ipc_json_str(request.method);
    body += R"(,"target":)";
    body += ipc_json_str(request.target);
    body += R"(,"remote_addr":)";
    body += ipc_json_str(request.remote_addr);
    // #323: the main process verifies the X-Matrix signature and forwards only
    // the verified peer identity. The raw Authorization header (access_token)
    // never crosses IPC, so a compromised worker cannot harvest the peer's
    // reusable origin/key/sig credential. sig_verified asserts the identity
    // was verified by main over the authenticated channel.
    body += R"(,"sig_verified":)";
    body += request.sig_verified ? "true" : "false";
    body += R"(,"verified_origin":)";
    body += ipc_json_str(request.verified_origin);
    body += R"(,"verified_key_id":)";
    body += ipc_json_str(request.verified_key_id);
    body += R"(,"headers":[)";
    auto first = true;
    for (auto const& hdr : request.headers)
    {
        // Defense-in-depth: never forward credential headers over IPC even if a
        // caller populated them. The worker receives only the verified identity.
        if (is_credential_header_name(hdr.name))
        {
            continue;
        }
        if (!first)
        {
            body += ',';
        }
        first = false;
        body += R"({"n":)";
        body += ipc_json_str(hdr.name);
        body += R"(,"v":)";
        body += ipc_json_str(hdr.value);
        body += '}';
    }
    body += R"(],"body":)";
    body += ipc_json_str(request.body);
    body += '}';
    return body;
}

auto deserialize_fed_request(std::string_view json) -> homeserver::LocalHttpRequest
{
    auto request = homeserver::LocalHttpRequest{};
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = object_of(parsed.value);
    if (parsed.error != canonicaljson::ParseError::none || obj == nullptr)
    {
        return request;
    }
    request.method = get_str(*obj, "method");
    request.target = get_str(*obj, "target");
    request.remote_addr = get_str(*obj, "remote_addr");
    // #323: the worker receives the verified identity, not the raw credential.
    request.sig_verified = get_bool(*obj, "sig_verified");
    request.verified_origin = get_str(*obj, "verified_origin");
    request.verified_key_id = get_str(*obj, "verified_key_id");
    request.body = get_str(*obj, "body");
    if (auto const* headers = get_array(*obj, "headers"))
    {
        extract_headers(*headers, request.headers);
    }
    return request;
}

auto serialize_fed_response(homeserver::LocalHttpResponse const& response) -> std::string
{
    auto result = std::string{};
    result.reserve(64U + response.body.size());
    result += R"({"type":"fed_response","status":)";
    result += std::to_string(response.status);
    result += R"(,"headers":[)";
    auto first = true;
    for (auto const& [name, value] : response.headers)
    {
        if (!first)
        {
            result += ',';
        }
        first = false;
        result += R"({"n":)";
        result += ipc_json_str(name);
        result += R"(,"v":)";
        result += ipc_json_str(value);
        result += '}';
    }
    result += R"(],"body":)";
    result += ipc_json_str(response.body);
    result += '}';
    return result;
}

auto deserialize_fed_response(std::string_view json) -> homeserver::LocalHttpResponse
{
    auto response = homeserver::LocalHttpResponse{};
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = object_of(parsed.value);
    if (parsed.error != canonicaljson::ParseError::none || obj == nullptr)
    {
        response.status = 500U;
        return response;
    }
    {
        auto const status = get_int(*obj, "status");
        if (status <= 0 || status > 999)
        {
            response.status = 500U;
        }
        else
        {
            response.status = static_cast<std::uint16_t>(status);
        }
    }
    response.body = get_str(*obj, "body");
    if (auto const* headers = get_array(*obj, "headers"))
    {
        extract_headers(*headers, response.headers);
    }
    return response;
}

auto serialize_outbound_http_request(http::OutboundRequest const& request) -> std::string
{
    auto body = std::string{};
    body.reserve(512U + request.body.size());
    body += R"({"type":"outbound_http_request","method":)";
    body += ipc_json_str(request.method);
    body += R"(,"url":)";
    body += ipc_json_str(request.url);
    body += R"(,"headers":[)";
    auto first = true;
    for (auto const& hdr : request.headers)
    {
        if (!first)
        {
            body += ',';
        }
        first = false;
        body += R"({"n":)";
        body += ipc_json_str(hdr.name);
        body += R"(,"v":)";
        body += ipc_json_str(hdr.value);
        body += '}';
    }
    body += R"(],"pinned_addresses":[)";
    first = true;
    for (auto const& addr : request.pinned_addresses)
    {
        if (!first)
        {
            body += ',';
        }
        first = false;
        body += ipc_json_str(addr);
    }
    body += R"(],"body":)";
    body += ipc_json_str(request.body);
    body += R"(,"connect_timeout":)";
    body += std::to_string(request.connect_timeout_seconds);
    body += R"(,"total_timeout":)";
    body += std::to_string(request.total_timeout_seconds);
    body += R"(,"max_body_bytes":)";
    body += std::to_string(request.max_response_body_bytes);
    body += '}';
    return body;
}

auto deserialize_outbound_http_request(std::string_view json) -> http::OutboundRequest
{
    auto request = http::OutboundRequest{};
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = object_of(parsed.value);
    if (parsed.error != canonicaljson::ParseError::none || obj == nullptr)
    {
        return request;
    }
    request.method = get_str(*obj, "method");
    request.url = get_str(*obj, "url");
    request.body = get_str(*obj, "body");
    if (auto const* headers = get_array(*obj, "headers"))
    {
        extract_headers(*headers, request.headers);
    }
    if (auto const* pinned = get_array(*obj, "pinned_addresses"))
    {
        for (auto const& elem : *pinned)
        {
            auto const* addr = std::get_if<std::string>(&elem.storage());
            if (addr != nullptr && !addr->empty())
            {
                request.pinned_addresses.push_back(*addr);
            }
        }
    }
    // Numeric fields are stored as int64 in the canonicaljson DOM; clamp into
    // the narrower unsigned fields. A negative or out-of-range value falls back
    // to 0, matching the prior from_chars behaviour on malformed input.
    request.connect_timeout_seconds = static_cast<std::uint32_t>(clamp_to_u32(get_int(*obj, "connect_timeout")));
    request.total_timeout_seconds = static_cast<std::uint32_t>(clamp_to_u32(get_int(*obj, "total_timeout")));
    request.max_response_body_bytes = static_cast<std::size_t>(clamp_to_u64(get_int(*obj, "max_body_bytes")));
    return request;
}

auto serialize_outbound_http_response(http::OutboundResult const& result) -> std::string
{
    auto body = std::string{};
    body.reserve(128U + result.response.body.size());
    body += R"({"type":"outbound_http_response","ok":)";
    body += result.ok ? "true" : "false";
    body += R"(,"http_status":)";
    body += std::to_string(result.response.status);
    body += R"(,"body":)";
    body += ipc_json_str(result.response.body);
    body += R"(,"error":)";
    body += ipc_json_str(result.ok ? std::string_view{} : http::outbound_error_name(result.error));
    body += R"(,"error_detail":)";
    body += ipc_json_str(result.error_detail);
    body += '}';
    return body;
}

auto deserialize_outbound_http_response(std::string_view json) -> http::OutboundResult
{
    auto result = http::OutboundResult{};
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = object_of(parsed.value);
    if (parsed.error != canonicaljson::ParseError::none || obj == nullptr)
    {
        result.error = http::OutboundError::network_error;
        return result;
    }
    result.ok = get_bool(*obj, "ok");
    result.response.status = static_cast<std::uint16_t>(clamp_to_u32(get_int(*obj, "http_status")));
    result.response.body = get_str(*obj, "body");
    result.error_detail = get_str(*obj, "error_detail");
    // error code is informational; callers inspect ok + http_status.
    result.error = result.ok ? http::OutboundError::none : http::OutboundError::network_error;
    return result;
}

} // namespace merovingian::ipc
