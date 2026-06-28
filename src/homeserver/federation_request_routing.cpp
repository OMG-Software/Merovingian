// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/federation_request_routing.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    // Minimal JSON string extractor used to read room_id from /send bodies.
    // Assumes the value is a simple string with the common JSON escapes; it is
    // intentionally small because it only runs for the federation routing path.
    [[nodiscard]] auto json_get_str(std::string_view json, std::string_view key) -> std::string
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

    // Federation endpoints where the room ID is a path segment. Order is not
    // important: the longest matching prefix is not required because the room ID
    // is always the first variable segment after the fixed prefix.
    [[nodiscard]] auto room_endpoint_prefixes() noexcept -> std::vector<std::string_view>
    {
        static auto const prefixes = std::vector<std::string_view>{
            "/_matrix/federation/v1/state/",
            "/_matrix/federation/v1/state_ids/",
            "/_matrix/federation/v1/invite/",
            "/_matrix/federation/v1/invite2/",
            "/_matrix/federation/v1/event_auth/",
            "/_matrix/federation/v1/backfill/",
            "/_matrix/federation/v1/get_missing_events/",
            "/_matrix/federation/v1/make_join/",
            "/_matrix/federation/v1/send_join/",
            "/_matrix/federation/v1/make_leave/",
            "/_matrix/federation/v1/send_leave/",
            "/_matrix/federation/v1/make_knock/",
            "/_matrix/federation/v1/send_knock/",
            "/_matrix/federation/v1/query/directory/",
            // v2 endpoints — required for correct shard routing; without these,
            // v2 requests fall through with no room_id and land on shard 0
            // regardless of which shard owns the room.
            "/_matrix/federation/v2/invite/",
            "/_matrix/federation/v2/send_join/",
            "/_matrix/federation/v2/send_leave/",
            "/_matrix/federation/v2/make_knock/",
            "/_matrix/federation/v2/send_knock/",
        };
        return prefixes;
    }

    // For /send/{txnId} the room ID is inside the request body. We extract the
    // first PDU's room_id. All PDUs in a transaction are for the same room in
    // practice; routing by the first PDU is sufficient for shard selection.
    [[nodiscard]] auto room_id_from_send_body(std::string_view body) -> std::string
    {
        auto const pdus_pos = body.find("\"pdus\":");
        if (pdus_pos == std::string_view::npos)
        {
            return {};
        }
        auto const array_start = body.find('[', pdus_pos);
        if (array_start == std::string_view::npos)
        {
            return {};
        }
        auto const first_obj = body.find('{', array_start);
        if (first_obj == std::string_view::npos)
        {
            return {};
        }
        // Track brace depth to find the matching '}' for the first PDU object.
        // A naive find('}') stops at the first nested object (e.g. "content" or
        // "hashes"), which excludes room_id if it appears after a nested field.
        auto depth = int{0};
        auto in_string = bool{false};
        auto obj_end = std::string_view::npos;
        for (auto i = first_obj; i < body.size(); ++i)
        {
            auto const ch = body[i];
            if (in_string)
            {
                if (ch == '\\')
                {
                    ++i; // skip escaped character
                }
                else if (ch == '"')
                {
                    in_string = false;
                }
            }
            else
            {
                if (ch == '"')
                {
                    in_string = true;
                }
                else if (ch == '{')
                {
                    ++depth;
                }
                else if (ch == '}')
                {
                    --depth;
                    if (depth == 0)
                    {
                        obj_end = i;
                        break;
                    }
                }
            }
        }
        if (obj_end == std::string_view::npos)
        {
            return {};
        }
        return json_get_str(body.substr(first_obj, obj_end - first_obj), "room_id");
    }

    [[nodiscard]] auto room_id_from_path_target(std::string_view target) -> std::string
    {
        for (auto const prefix : room_endpoint_prefixes())
        {
            if (target.size() > prefix.size() && target.substr(0U, prefix.size()) == prefix)
            {
                auto const remainder = target.substr(prefix.size());
                // Stop at next path separator or query string.
                auto const end = remainder.find_first_of("/?");
                return std::string{remainder.substr(0U, end)};
            }
        }
        return {};
    }

} // namespace

auto federation_worker_room_id_from_request(LocalHttpRequest const& request) -> std::string
{
    if (request.target.find("/_matrix/federation/v1/send/") != std::string::npos)
    {
        return room_id_from_send_body(request.body);
    }
    return room_id_from_path_target(request.target);
}

} // namespace merovingian::homeserver
