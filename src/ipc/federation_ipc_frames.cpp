// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/federation_ipc_frames.hpp"

#include "merovingian/http/request.hpp"

#include <charconv>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::ipc
{

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
    auto const needle = std::string{"\""} + std::string{key} + "\":\"";
    auto const pos = json.find(needle);
    if (pos == std::string_view::npos)
    {
        return {};
    }
    auto i = pos + needle.size();
    auto result = std::string{};
    while (i < json.size())
    {
        auto const ch = json[i];
        if (ch == '\"')
        {
            break;
        }
        if (ch == '\\' && i + 1 < json.size())
        {
            ++i;
            switch (json[i])
            {
            case '\"':
                result += '\"';
                break;
            case '\\':
                result += '\\';
                break;
            case 'b':
                result += '\b';
                break;
            case 'f':
                result += '\f';
                break;
            case 'n':
                result += '\n';
                break;
            case 'r':
                result += '\r';
                break;
            case 't':
                result += '\t';
                break;
            default:
                result += json[i];
                break;
            }
        }
        else
        {
            result += ch;
        }
        ++i;
    }
    return result;
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
    body += R"(],"body":)";
    body += ipc_json_str(request.body);
    body += '}';
    return body;
}

auto deserialize_fed_request(std::string_view json) -> homeserver::LocalHttpRequest
{
    auto request = homeserver::LocalHttpRequest{};
    request.method = ipc_json_get_str(json, "method");
    request.target = ipc_json_get_str(json, "target");
    request.remote_addr = ipc_json_get_str(json, "remote_addr");
    request.body = ipc_json_get_str(json, "body");

    auto const headers_key = std::string_view{R"("headers":[)"};
    auto const hpos = json.find(headers_key);
    if (hpos != std::string_view::npos)
    {
        auto pos = hpos + headers_key.size();
        while (pos < json.size() && json[pos] != ']')
        {
            auto const obj_start = json.find('{', pos);
            if (obj_start == std::string_view::npos)
            {
                break;
            }
            auto const obj_end = json.find('}', obj_start);
            if (obj_end == std::string_view::npos)
            {
                break;
            }
            auto const obj = json.substr(obj_start, obj_end - obj_start + 1U);
            auto name = ipc_json_get_str(obj, "n");
            auto value = ipc_json_get_str(obj, "v");
            if (!name.empty())
            {
                request.headers.emplace_back(std::move(name), std::move(value));
            }
            pos = obj_end + 1U;
        }
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

namespace
{

    [[nodiscard]] auto ipc_json_get_u64(std::string_view json, std::string_view key) -> std::uint64_t
    {
        auto const needle = std::string{"\""} + std::string{key} + "\":";
        auto const pos = json.find(needle);
        if (pos == std::string_view::npos)
        {
            return 0U;
        }
        auto i = pos + needle.size();
        auto skip = std::size_t{0U};
        while (i + skip < json.size() && (json[i + skip] == ' ' || json[i + skip] == '\t'))
        {
            ++skip;
        }
        i += skip;
        auto value = std::uint64_t{0U};
        auto start = json.data() + i;
        auto end = json.data() + json.size();
        std::ignore = std::from_chars(start, end, value);
        return value;
    }

} // namespace

auto deserialize_fed_response(std::string_view json) -> homeserver::LocalHttpResponse
{
    auto response = homeserver::LocalHttpResponse{};
    {
        auto const value = ipc_json_get_u64(json, "status");
        if (value == 0U || value > 999U)
        {
            response.status = 500U;
        }
        else
        {
            response.status = static_cast<std::uint16_t>(value);
        }
    }
    response.body = ipc_json_get_str(json, "body");

    auto const headers_key = std::string_view{R"("headers":[)"};
    auto const hpos = json.find(headers_key);
    if (hpos != std::string_view::npos)
    {
        auto pos = hpos + headers_key.size();
        while (pos < json.size() && json[pos] != ']')
        {
            auto const obj_start = json.find('{', pos);
            if (obj_start == std::string_view::npos)
            {
                break;
            }
            auto const obj_end = json.find('}', obj_start);
            if (obj_end == std::string_view::npos)
            {
                break;
            }
            auto const obj = json.substr(obj_start, obj_end - obj_start + 1U);
            auto name = ipc_json_get_str(obj, "n");
            auto value = ipc_json_get_str(obj, "v");
            if (!name.empty())
            {
                response.headers.emplace_back(std::move(name), std::move(value));
            }
            pos = obj_end + 1U;
        }
    }

    return response;
}

} // namespace merovingian::ipc
