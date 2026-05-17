// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/membership_endpoints.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto split_two(std::string_view suffix) -> std::optional<std::pair<std::string, std::string>>
    {
        auto const slash = suffix.find('/');
        if (slash == std::string_view::npos || slash == 0U || slash + 1U >= suffix.size())
        {
            return std::nullopt;
        }
        auto first = std::string{suffix.substr(0U, slash)};
        auto second = std::string{suffix.substr(slash + 1U)};
        if (second.find('/') != std::string::npos)
        {
            return std::nullopt;
        }
        return std::pair{std::move(first), std::move(second)};
    }

    [[nodiscard]] auto strip_prefix(std::string_view target, std::string_view prefix) -> std::string_view
    {
        if (target.size() <= prefix.size() || target.substr(0U, prefix.size()) != prefix)
        {
            return {};
        }
        return target.substr(prefix.size());
    }

    [[nodiscard]] auto find_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto canonical_serialize(canonicaljson::Value const& value) -> std::string
    {
        auto const out = canonicaljson::serialize_canonical(value);
        return out.error == canonicaljson::CanonicalJsonError::none ? out.output : std::string{};
    }

    [[nodiscard]] auto path_prefix(FederationEndpoint endpoint) -> std::string_view
    {
        switch (endpoint)
        {
        case FederationEndpoint::make_join:
            return "/_matrix/federation/v1/make_join/";
        case FederationEndpoint::send_join:
            return ""; // handled below — two versions
        case FederationEndpoint::make_leave:
            return "/_matrix/federation/v1/make_leave/";
        case FederationEndpoint::send_leave:
            return "";
        case FederationEndpoint::make_knock:
            return "/_matrix/federation/v1/make_knock/";
        case FederationEndpoint::send_knock:
            return "/_matrix/federation/v1/send_knock/";
        default:
            return "";
        }
    }

    [[nodiscard]] auto strip_send_prefix(FederationEndpoint endpoint, std::string_view target) -> std::string_view
    {
        // send_join / send_leave appear at both v1 and v2 prefixes; strip
        // whichever matches.
        if (endpoint == FederationEndpoint::send_join)
        {
            if (auto suffix = strip_prefix(target, "/_matrix/federation/v2/send_join/"); !suffix.empty())
            {
                return suffix;
            }
            return strip_prefix(target, "/_matrix/federation/v1/send_join/");
        }
        if (endpoint == FederationEndpoint::send_leave)
        {
            if (auto suffix = strip_prefix(target, "/_matrix/federation/v2/send_leave/"); !suffix.empty())
            {
                return suffix;
            }
            return strip_prefix(target, "/_matrix/federation/v1/send_leave/");
        }
        return strip_prefix(target, path_prefix(endpoint));
    }

} // namespace

auto parse_membership_path(FederationEndpoint endpoint, std::string_view target)
    -> std::optional<MembershipPathParams>
{
    auto const target_path = [target] {
        auto const q = target.find('?');
        return q == std::string_view::npos ? target : target.substr(0U, q);
    }();
    auto suffix = std::string_view{};
    switch (endpoint)
    {
    case FederationEndpoint::make_join:
    case FederationEndpoint::make_leave:
    case FederationEndpoint::make_knock:
    case FederationEndpoint::send_knock:
        suffix = strip_prefix(target_path, path_prefix(endpoint));
        break;
    case FederationEndpoint::send_join:
    case FederationEndpoint::send_leave:
        suffix = strip_send_prefix(endpoint, target_path);
        break;
    default:
        return std::nullopt;
    }
    if (suffix.empty())
    {
        return std::nullopt;
    }
    auto split = split_two(suffix);
    if (!split.has_value())
    {
        return std::nullopt;
    }
    return MembershipPathParams{std::move(split->first), std::move(split->second)};
}

auto parse_backfill_query(std::string_view target) -> std::optional<BackfillRequest>
{
    auto const q_position = target.find('?');
    if (q_position == std::string_view::npos)
    {
        return std::nullopt;
    }
    auto const path = target.substr(0U, q_position);
    auto const query = target.substr(q_position + 1U);
    constexpr auto prefix = std::string_view{"/_matrix/federation/v1/backfill/"};
    if (path.size() <= prefix.size() || path.substr(0U, prefix.size()) != prefix)
    {
        return std::nullopt;
    }
    auto request = BackfillRequest{};
    request.room_id = std::string{path.substr(prefix.size())};
    if (request.room_id.empty() || request.room_id.find('/') != std::string::npos)
    {
        return std::nullopt;
    }
    auto cursor = query;
    while (!cursor.empty())
    {
        auto const amp = cursor.find('&');
        auto const segment = cursor.substr(0U, amp);
        auto const eq = segment.find('=');
        auto const key = segment.substr(0U, eq);
        auto const value = eq == std::string_view::npos ? std::string_view{} : segment.substr(eq + 1U);
        if (key == "v" && !value.empty())
        {
            request.event_ids.emplace_back(value);
        }
        else if (key == "limit" && !value.empty())
        {
            // strtoull tolerates trailing garbage which we treat as malformed.
            auto buffer = std::string{value};
            char* end = nullptr;
            auto const parsed = std::strtoull(buffer.c_str(), &end, 10);
            if (end == nullptr || *end != '\0')
            {
                return std::nullopt;
            }
            request.limit = static_cast<std::size_t>(parsed);
        }
        if (amp == std::string_view::npos)
        {
            break;
        }
        cursor = cursor.substr(amp + 1U);
    }
    if (request.event_ids.empty())
    {
        return std::nullopt;
    }
    return request;
}

auto parse_invite_body(std::string_view body, std::string_view room_id, std::string_view event_id,
                       FederationEndpoint endpoint) -> std::optional<InviteRequest>
{
    if (body.empty() || body.front() != '{')
    {
        return std::nullopt;
    }
    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* root = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    if (root == nullptr)
    {
        return std::nullopt;
    }

    auto request = InviteRequest{};
    request.room_id = std::string{room_id};
    request.event_id = std::string{event_id};

    if (endpoint == FederationEndpoint::invite)
    {
        // v2 invite carries { room_version, event, invite_room_state }.
        // v1 invite body IS the event itself.
        auto const* version = find_member(*root, "room_version");
        auto const* event_value = find_member(*root, "event");
        if (version != nullptr && event_value != nullptr)
        {
            auto const* version_text = std::get_if<std::string>(&version->storage());
            if (version_text == nullptr || version_text->empty())
            {
                return std::nullopt;
            }
            request.room_version = *version_text;
            auto event_json = canonical_serialize(*event_value);
            if (event_json.empty())
            {
                return std::nullopt;
            }
            request.invite_event_json = std::move(event_json);
            if (auto const* state_value = find_member(*root, "invite_room_state"); state_value != nullptr)
            {
                auto const* state_array = std::get_if<canonicaljson::Array>(&state_value->storage());
                if (state_array != nullptr)
                {
                    for (auto const& state_entry : *state_array)
                    {
                        if (auto entry_json = canonical_serialize(state_entry); !entry_json.empty())
                        {
                            request.invite_room_state_json.push_back(std::move(entry_json));
                        }
                    }
                }
            }
            return request;
        }
        // Fall through: treat body as v1-style raw event.
        request.invite_event_json = std::string{body};
        return request;
    }
    return std::nullopt;
}

} // namespace merovingian::federation
