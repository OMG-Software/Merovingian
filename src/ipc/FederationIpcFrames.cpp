// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/FederationIpcFrames.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/federation/PublicRoomsRefusal.hpp"
#include "merovingian/federation/PublicRooms.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/http/OutboundResult.hpp"
#include "merovingian/ipc/MembershipTemplateIngest.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
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

    // Reads a string written by append_lossless_member (defined below, with the base64 helpers).
    [[nodiscard]] auto get_lossless_str(canonicaljson::Object const& obj, std::string_view key) -> std::string;

    // Extracts an array of {"n":...,"v":...} header objects into a container of
    // {name, value} pairs. Works for http::Header, OutboundHeader, and
    // std::pair<std::string, std::string> (all two-string aggregate/brace-init).
    // A value that was not valid UTF-8 arrives as "v_b64" and is restored exactly.
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
            auto value = get_lossless_str(*obj, "v");
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

    // Encodes bytes as standard padded base64 for embedding in an IPC JSON
    // frame's "body" field. Response bodies (HTTP response bytes relayed
    // between the federation worker and main) are otherwise embedded via
    // ipc_json_str, which `"`/`\`-escapes byte-for-byte and turns raw control
    // bytes into `\u00XX` (6 bytes for 1). A response body already at
    // http::OutboundRequest::max_response_body_bytes (16 MiB by default) can
    // therefore need well over the IPC frame cap once wrapped, get silently
    // dropped by the oversize-frame guard, and surface to the caller as a
    // plain IPC timeout — exactly what large-room send_join responses hit.
    // Base64 has a fixed, content-independent 4/3 expansion, so the frame cap
    // can be sized against a known worst case instead of the escaped size of
    // whatever bytes a remote peer happened to send back.
    [[nodiscard]] auto base64_encode_body(std::string_view bytes) -> std::string
    {
        auto const encoded = crypto::base64_original_encode(bytes);
        return encoded.value_or("");
    }

    // Decodes a base64 "body" field produced by base64_encode_body. Returns
    // an empty string on malformed input, matching the prior fallback shape
    // for other malformed IPC fields.
    [[nodiscard]] auto base64_decode_body(std::string_view encoded) -> std::string
    {
        auto const decoded = crypto::base64_original_decode(encoded);
        return decoded.value_or("");
    }

    // Appends `"key":<value>` as a JSON string member when `value` is valid UTF-8 and
    // `"key_b64":<base64>` when it is not, so a request field that carries raw bytes from a
    // remote server reaches the peer exactly, in a frame that is valid UTF-8 (ADR-0321). Valid
    // text keeps the plain form: it stays readable and costs no 4/3 expansion.
    auto append_lossless_member(std::string& out, std::string_view key, std::string_view value) -> void
    {
        out += '"';
        out += key;
        if (canonicaljson::utf8_is_valid(value))
        {
            out += "\":";
            out += ipc_json_str(value);
            return;
        }
        out += "_b64\":";
        out += ipc_json_str(base64_encode_body(value));
    }

    [[nodiscard]] auto get_lossless_str(canonicaljson::Object const& obj, std::string_view key) -> std::string
    {
        if (find_member(obj, key) != nullptr)
        {
            return get_str(obj, key);
        }
        return base64_decode_body(get_str(obj, std::string{key} + "_b64"));
    }

    // Length of the UTF-8 sequence a lead byte announces, or 0 for a byte that cannot
    // start one (a continuation byte, 0xF8 and up).
    [[nodiscard]] auto utf8_sequence_length(unsigned char lead) noexcept -> std::size_t
    {
        if ((lead & 0xE0U) == 0xC0U)
        {
            return 2U;
        }
        if ((lead & 0xF0U) == 0xE0U)
        {
            return 3U;
        }
        if ((lead & 0xF8U) == 0xF0U)
        {
            return 4U;
        }
        return 0U;
    }

} // namespace

auto ipc_json_str(std::string_view s) -> std::string
{
    auto result = std::string{};
    result.reserve(s.size() + 2U);
    result += '"';
    auto index = std::size_t{0U};
    while (index < s.size())
    {
        auto const ch = static_cast<unsigned char>(s[index]);
        if (ch >= 0x80U)
        {
            // The peer's parser rejects a frame that is not valid UTF-8 as a whole
            // (ADR-0321), so a byte sequence that is not valid is replaced with U+FFFD,
            // one replacement per bad byte, and never copied. Bytes that must survive
            // exactly use the "<key>_b64" form instead (append_lossless_member).
            auto const length = utf8_sequence_length(ch);
            if (length > 0U && index + length <= s.size() && canonicaljson::utf8_is_valid(s.substr(index, length)))
            {
                result.append(s.substr(index, length));
                index += length;
            }
            else
            {
                result += "\xEF\xBF\xBD";
                ++index;
            }
            continue;
        }
        ++index;
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

auto ipc_json_get_u64(std::string_view json, std::string_view key) -> std::uint64_t
{
    auto const parsed = canonicaljson::parse_json(json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return 0U;
    }
    auto const* obj = object_of(parsed.value);
    if (obj == nullptr)
    {
        return 0U;
    }
    auto const value = get_int(*obj, key);
    return value > 0 ? static_cast<std::uint64_t>(value) : 0U;
}

auto serialize_fed_request(homeserver::LocalHttpRequest const& request) -> std::string
{
    auto body = std::string{};
    body.reserve(512U + request.body.size());
    body += R"({"type":"fed_request","method":)";
    body += ipc_json_str(request.method);
    // The target, header values and body are bytes a remote server chose; the HTTP parser lets
    // 0x80-0xFF through. Each is carried exactly (append_lossless_member), because a frame the
    // worker's parser rejects would end its channel (F-35, ADR-0321).
    body += ',';
    append_lossless_member(body, "target", request.target);
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
        body += ',';
        append_lossless_member(body, "v", hdr.value);
        body += '}';
    }
    body += "],";
    append_lossless_member(body, "body", request.body);
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
    request.target = get_lossless_str(*obj, "target");
    request.remote_addr = get_str(*obj, "remote_addr");
    // #323: the worker receives the verified identity, not the raw credential.
    request.sig_verified = get_bool(*obj, "sig_verified");
    request.verified_origin = get_str(*obj, "verified_origin");
    request.verified_key_id = get_str(*obj, "verified_key_id");
    request.body = get_lossless_str(*obj, "body");
    if (auto const* headers = get_array(*obj, "headers"))
    {
        extract_headers(*headers, request.headers);
    }
    return request;
}

auto serialize_fed_response(homeserver::LocalHttpResponse const& response) -> std::string
{
    auto result = std::string{};
    // Base64 inflates the body ~4/3x; reserve against that instead of the raw
    // size so appending the encoded body does not reallocate.
    result.reserve(64U + (response.body.size() * 4U) / 3U + 4U);
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
    // The body is base64-encoded before framing (see base64_encode_body) so
    // its contribution to the frame size is bounded by a fixed 4/3 expansion
    // instead of the content-dependent blowup of raw JSON-string escaping.
    result += R"(],"body":)";
    result += ipc_json_str(base64_encode_body(response.body));
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
    response.body = base64_decode_body(get_str(*obj, "body"));
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
    // Base64 inflates the body ~4/3x; reserve against that instead of the raw
    // size so appending the encoded body does not reallocate.
    body.reserve(128U + (result.response.body.size() * 4U) / 3U + 4U);
    body += R"({"type":"outbound_http_response","ok":)";
    body += result.ok ? "true" : "false";
    body += R"(,"http_status":)";
    body += std::to_string(result.response.status);
    // The body is base64-encoded before framing (see base64_encode_body) so
    // its contribution to the frame size is bounded by a fixed 4/3 expansion
    // instead of the content-dependent blowup of raw JSON-string escaping —
    // a large-room send_join response near max_response_body_bytes otherwise
    // busts the IPC frame cap after escaping and is silently dropped.
    body += R"(,"body":)";
    body += ipc_json_str(base64_encode_body(result.response.body));
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
    result.response.body = base64_decode_body(get_str(*obj, "body"));
    result.error_detail = get_str(*obj, "error_detail");
    // Preserve the specific OutboundError variant across IPC rather than
    // collapsing every failure to network_error. Callers still treat ok as the
    // primary signal; the error code is retained for logging and diagnostics.
    result.error = result.ok ? http::OutboundError::none : http::outbound_error_from_name(get_str(*obj, "error"));
    return result;
}

auto serialize_room_sync_notification(std::string_view room_id, std::uint64_t generation) -> std::string
{
    auto body = std::string{R"({"type":"room_sync","room_id":)"};
    body += ipc_json_str(room_id);
    body += R"(,"generation":)";
    body += std::to_string(generation);
    body += '}';
    return body;
}

auto serialize_room_sync_result(std::string_view room_id, std::string_view state, std::uint64_t generation)
    -> std::string
{
    auto body = std::string{R"({"type":"room_sync_result","room_id":)"};
    body += ipc_json_str(room_id);
    body += R"(,"state":)";
    body += ipc_json_str(state);
    body += R"(,"generation":)";
    body += std::to_string(generation);
    body += '}';
    return body;
}

namespace
{

    auto append_string_array(std::string& body, std::vector<std::string> const& values) -> void
    {
        body += '[';
        auto first = true;
        for (auto const& value : values)
        {
            if (!first)
            {
                body += ',';
            }
            first = false;
            body += ipc_json_str(value);
        }
        body += ']';
    }

    [[nodiscard]] auto get_string_array(canonicaljson::Object const& obj, std::string_view key)
        -> std::vector<std::string>
    {
        auto values = std::vector<std::string>{};
        auto const* array = get_array(obj, key);
        if (array == nullptr)
        {
            return values;
        }
        for (auto const& entry : *array)
        {
            if (auto const* text = std::get_if<std::string>(&entry.storage()); text != nullptr)
            {
                values.push_back(*text);
            }
        }
        return values;
    }

} // namespace

auto serialize_membership_template_ingest(MembershipTemplateIngest const& request) -> std::string
{
    auto body = std::string{R"({"type":"membership_template_ingest","room_id":)"};
    body += ipc_json_str(request.room_id);
    body += R"(,"user_id":)";
    body += ipc_json_str(request.user_id);
    body += R"(,"supported_versions":)";
    append_string_array(body, request.supported_versions);
    body += '}';
    return body;
}

auto deserialize_membership_template_ingest(std::string_view json) -> std::optional<MembershipTemplateIngest>
{
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = parsed.error == canonicaljson::ParseError::none ? object_of(parsed.value) : nullptr;
    if (obj == nullptr)
    {
        return std::nullopt;
    }
    auto request = MembershipTemplateIngest{get_str(*obj, "room_id"), get_str(*obj, "user_id"),
                                            get_string_array(*obj, "supported_versions")};
    if (request.room_id.empty() || request.user_id.empty())
    {
        return std::nullopt;
    }
    return request;
}

auto serialize_membership_template_ingest_result(std::optional<federation::MembershipEventTemplate> const& result)
    -> std::string
{
    auto body = std::string{R"({"type":"membership_template_ingest_result","found":)"};
    if (!result.has_value())
    {
        body += "false}";
        return body;
    }
    auto const& tmpl = *result;
    body += "true";
    body += R"(,"room_id":)";
    body += ipc_json_str(tmpl.room_id);
    body += R"(,"user_id":)";
    body += ipc_json_str(tmpl.user_id);
    body += R"(,"membership":)";
    body += ipc_json_str(tmpl.membership);
    body += R"(,"room_version":)";
    body += ipc_json_str(tmpl.room_version);
    body += R"(,"origin":)";
    body += ipc_json_str(tmpl.origin);
    body += R"(,"origin_server_ts":)";
    body += std::to_string(tmpl.origin_server_ts);
    body += R"(,"prev_events":)";
    append_string_array(body, tmpl.prev_events);
    body += R"(,"auth_events":)";
    append_string_array(body, tmpl.auth_events);
    body += R"(,"depth":)";
    body += std::to_string(tmpl.depth);
    body += R"(,"content_json":)";
    body += ipc_json_str(tmpl.content_json);
    body += R"(,"reason":)";
    body += ipc_json_str(tmpl.reason);
    body += R"(,"error_status":)";
    body += std::to_string(tmpl.error_status);
    body += '}';
    return body;
}

auto deserialize_membership_template_ingest_result(std::string_view json)
    -> std::optional<federation::MembershipEventTemplate>
{
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = parsed.error == canonicaljson::ParseError::none ? object_of(parsed.value) : nullptr;
    if (obj == nullptr || !get_bool(*obj, "found"))
    {
        return std::nullopt;
    }
    auto tmpl = federation::MembershipEventTemplate{};
    tmpl.room_id = get_str(*obj, "room_id");
    tmpl.user_id = get_str(*obj, "user_id");
    tmpl.membership = get_str(*obj, "membership");
    tmpl.room_version = get_str(*obj, "room_version");
    tmpl.origin = get_str(*obj, "origin");
    tmpl.origin_server_ts = get_int(*obj, "origin_server_ts");
    tmpl.prev_events = get_string_array(*obj, "prev_events");
    tmpl.auth_events = get_string_array(*obj, "auth_events");
    tmpl.depth = get_int(*obj, "depth");
    tmpl.content_json = get_str(*obj, "content_json");
    tmpl.reason = get_str(*obj, "reason");
    auto const status = get_int(*obj, "error_status");
    tmpl.error_status = status >= 400 && status <= 599 ? static_cast<std::uint16_t>(status) : std::uint16_t{500U};
    return tmpl;
}

auto serialize_public_rooms_ingest(federation::PublicRoomsRequest const& request) -> std::string
{
    auto body = std::string{R"({"type":"public_rooms_ingest","request":)"};
    body += ipc_json_str(federation::serialize_public_rooms_request(request));
    body += '}';
    return body;
}

auto deserialize_public_rooms_ingest(std::string_view json) -> std::optional<federation::PublicRoomsRequest>
{
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = parsed.error == canonicaljson::ParseError::none ? object_of(parsed.value) : nullptr;
    if (obj == nullptr)
    {
        return std::nullopt;
    }
    auto const request_json = get_str(*obj, "request");
    if (request_json.empty())
    {
        return std::nullopt;
    }
    auto request = federation::parse_public_rooms_body(request_json);
    if (std::holds_alternative<federation::PublicRoomsRefusal>(request))
    {
        return std::nullopt;
    }
    return std::get<federation::PublicRoomsRequest>(std::move(request));
}

auto serialize_public_rooms_ingest_result(std::optional<std::string> const& body) -> std::string
{
    auto result = std::string{R"({"type":"public_rooms_ingest_result","found":)"};
    if (!body.has_value())
    {
        result += "false}";
        return result;
    }
    result += R"(true,"body":)";
    result += ipc_json_str(*body);
    result += '}';
    return result;
}

auto deserialize_public_rooms_ingest_result(std::string_view json) -> std::optional<std::string>
{
    auto const parsed = canonicaljson::parse_json(json);
    auto const* obj = parsed.error == canonicaljson::ParseError::none ? object_of(parsed.value) : nullptr;
    if (obj == nullptr || !get_bool(*obj, "found"))
    {
        return std::nullopt;
    }
    auto body = get_str(*obj, "body");
    if (body.empty())
    {
        return std::nullopt;
    }
    return body;
}

} // namespace merovingian::ipc
