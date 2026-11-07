// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/public_rooms.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/core/FoldedSubstringMatcher.hpp"
#include "merovingian/federation/PublicRoomsFilter.hpp"
#include "merovingian/federation/PublicRoomsRefusal.hpp"
#include "merovingian/federation/PublicRoomsRequest.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <variant>

namespace merovingian::federation
{

namespace
{

    [[nodiscard]] auto refuse(std::string_view errcode, std::string_view message) -> PublicRoomsRefusal
    {
        return PublicRoomsRefusal{std::string{errcode}, std::string{message}};
    }

    [[nodiscard]] auto member_of(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key && member.value)
            {
                return member.value.get();
            }
        }
        return nullptr;
    }

    // A paging value from the wire: decimal digits that fit a size_t, nothing else. `since` is a token this
    // server issued, so anything else was never issued by it, and starting again from the first page would
    // loop a paginating server forever.
    [[nodiscard]] auto parse_count(std::string_view text) -> std::optional<std::size_t>
    {
        auto value = std::size_t{0U};
        auto const* const end = text.data() + text.size();
        auto const [ptr, ec] = std::from_chars(text.data(), end, value);
        if (ec != std::errc{} || ptr != end)
        {
            return std::nullopt;
        }
        return value;
    }

    [[nodiscard]] auto network_choice_refusal(PublicRoomsRequest const& request) -> std::optional<PublicRoomsRefusal>
    {
        // Spec: `third_party_instance_id` "Can only be used if include_all_networks is false."
        if (request.include_all_networks && !request.third_party_instance_id.empty())
        {
            return refuse("M_INVALID_PARAM",
                          "third_party_instance_id can only be used if include_all_networks is false");
        }
        return std::nullopt;
    }

} // namespace

auto parse_public_rooms_filter(canonicaljson::Value const& filter) -> PublicRoomsFilterResult
{
    auto const* object = std::get_if<canonicaljson::Object>(&filter.storage());
    if (object == nullptr)
    {
        return refuse("M_BAD_JSON", "filter must be an object");
    }
    auto parsed = PublicRoomsFilter{};
    if (auto const* term = member_of(*object, "generic_search_term"); term != nullptr)
    {
        auto const* text = std::get_if<std::string>(&term->storage());
        if (text == nullptr)
        {
            return refuse("M_BAD_JSON", "generic_search_term must be a string");
        }
        // Refused, not truncated: a cut term returns the wrong rooms (ADR-0330).
        if (text->size() > core::max_search_term_bytes)
        {
            return refuse("M_TOO_LARGE", "generic_search_term is longer than " +
                                             std::to_string(core::max_search_term_bytes) + " bytes");
        }
        parsed.generic_search_term = *text;
    }
    if (auto const* types = member_of(*object, "room_types"); types != nullptr)
    {
        auto const* list = std::get_if<canonicaljson::Array>(&types->storage());
        if (list == nullptr)
        {
            return refuse("M_BAD_JSON", "room_types must be a list");
        }
        auto wanted = std::vector<std::optional<std::string>>{};
        wanted.reserve(list->size());
        for (auto const& entry : *list)
        {
            if (std::holds_alternative<std::nullptr_t>(entry.storage()))
            {
                wanted.emplace_back(std::nullopt);
            }
            else if (auto const* type = std::get_if<std::string>(&entry.storage()); type != nullptr)
            {
                wanted.emplace_back(*type);
            }
            else
            {
                return refuse("M_BAD_JSON", "room_types may hold only strings and null");
            }
        }
        parsed.room_types = std::move(wanted);
    }
    return parsed;
}

auto public_rooms_filter_value(PublicRoomsFilter const& filter) -> canonicaljson::Value
{
    auto object = canonicaljson::Object{};
    if (!filter.generic_search_term.empty())
    {
        object.push_back(
            canonicaljson::make_member("generic_search_term", canonicaljson::Value{filter.generic_search_term}));
    }
    if (filter.room_types.has_value())
    {
        auto types = canonicaljson::Array{};
        types.reserve(filter.room_types->size());
        for (auto const& type : *filter.room_types)
        {
            types.push_back(type.has_value() ? canonicaljson::Value{*type} : canonicaljson::Value{nullptr});
        }
        object.push_back(canonicaljson::make_member("room_types", canonicaljson::Value{std::move(types)}));
    }
    return canonicaljson::Value{std::move(object)};
}

auto parse_public_rooms_body(std::string_view body) -> PublicRoomsRequestResult
{
    auto request = PublicRoomsRequest{};
    if (body.empty())
    {
        return request;
    }
    auto const parsed = canonicaljson::parse_json(body);
    auto const* object = parsed.error == canonicaljson::ParseError::none
                             ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                             : nullptr;
    if (object == nullptr)
    {
        return refuse("M_NOT_JSON", "request body must be a JSON object");
    }
    if (auto const* filter = member_of(*object, "filter"); filter != nullptr)
    {
        auto parsed_filter = parse_public_rooms_filter(*filter);
        if (auto* const refusal = std::get_if<PublicRoomsRefusal>(&parsed_filter); refusal != nullptr)
        {
            return std::move(*refusal);
        }
        request.filter = std::get<PublicRoomsFilter>(std::move(parsed_filter));
    }
    if (auto const* limit = member_of(*object, "limit"); limit != nullptr)
    {
        auto const* number = std::get_if<std::int64_t>(&limit->storage());
        if (number == nullptr || *number < 0)
        {
            return refuse("M_BAD_JSON", "limit must be a non-negative integer");
        }
        if (*number > 0)
        {
            request.limit = static_cast<std::size_t>(*number);
        }
    }
    if (auto const* since = member_of(*object, "since"); since != nullptr)
    {
        auto const* text = std::get_if<std::string>(&since->storage());
        if (text == nullptr)
        {
            return refuse("M_BAD_JSON", "since must be a string");
        }
        if (!text->empty())
        {
            auto const offset = parse_count(*text);
            if (!offset.has_value())
            {
                return refuse("M_INVALID_PARAM", "since is not a pagination token from this server");
            }
            request.since_offset = *offset;
        }
    }
    if (auto const* networks = member_of(*object, "include_all_networks"); networks != nullptr)
    {
        auto const* flag = std::get_if<bool>(&networks->storage());
        if (flag == nullptr)
        {
            return refuse("M_BAD_JSON", "include_all_networks must be a boolean");
        }
        request.include_all_networks = *flag;
    }
    if (auto const* instance = member_of(*object, "third_party_instance_id"); instance != nullptr)
    {
        auto const* text = std::get_if<std::string>(&instance->storage());
        if (text == nullptr)
        {
            return refuse("M_BAD_JSON", "third_party_instance_id must be a string");
        }
        request.third_party_instance_id = *text;
    }
    if (auto refusal = network_choice_refusal(request); refusal.has_value())
    {
        return *std::move(refusal);
    }
    return request;
}

auto parse_public_rooms_query(std::string_view limit, std::string_view since, std::string_view include_all_networks,
                              std::string_view third_party_instance_id) -> PublicRoomsRequestResult
{
    auto request = PublicRoomsRequest{};
    if (!limit.empty())
    {
        auto const parsed = parse_count(limit);
        if (!parsed.has_value())
        {
            return refuse("M_INVALID_PARAM", "limit must be a non-negative integer");
        }
        // Spec: "Defaults to 0 (no limit)."
        if (*parsed > 0U)
        {
            request.limit = *parsed;
        }
    }
    if (!since.empty())
    {
        auto const parsed = parse_count(since);
        if (!parsed.has_value())
        {
            return refuse("M_INVALID_PARAM", "since is not a pagination token from this server");
        }
        request.since_offset = *parsed;
    }
    if (!include_all_networks.empty() && include_all_networks != "true" && include_all_networks != "false")
    {
        return refuse("M_INVALID_PARAM", "include_all_networks must be true or false");
    }
    request.include_all_networks = include_all_networks == "true";
    request.third_party_instance_id = std::string{third_party_instance_id};
    if (auto refusal = network_choice_refusal(request); refusal.has_value())
    {
        return *std::move(refusal);
    }
    return request;
}

auto serialize_public_rooms_request(PublicRoomsRequest const& request) -> std::string
{
    auto body = canonicaljson::Object{};
    if (!request.filter.generic_search_term.empty() || request.filter.room_types.has_value())
    {
        body.push_back(canonicaljson::make_member("filter", public_rooms_filter_value(request.filter)));
    }
    if (request.limit.has_value())
    {
        // A GET's limit can be any size_t, but a JSON integer stops at 2^53 - 1. The limit is a maximum, and
        // the operator's page size is far below that, so holding it there answers the same page.
        auto constexpr max_json_integer = std::size_t{9007199254740991U};
        body.push_back(canonicaljson::make_member(
            "limit", canonicaljson::Value{static_cast<std::int64_t>(std::min(*request.limit, max_json_integer))}));
    }
    if (request.since_offset > 0U)
    {
        body.push_back(canonicaljson::make_member("since", canonicaljson::Value{std::to_string(request.since_offset)}));
    }
    if (request.include_all_networks)
    {
        body.push_back(canonicaljson::make_member("include_all_networks", canonicaljson::Value{true}));
    }
    if (!request.third_party_instance_id.empty())
    {
        body.push_back(canonicaljson::make_member("third_party_instance_id",
                                                  canonicaljson::Value{request.third_party_instance_id}));
    }
    return canonicaljson::serialize_canonical(canonicaljson::Value{std::move(body)}).output;
}

} // namespace merovingian::federation
