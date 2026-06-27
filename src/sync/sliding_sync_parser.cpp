// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/sliding_sync_parser.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/core/query_params.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::sync
{
namespace
{

    // ── canonicaljson accessor helpers ──────────────────────────────────────

    [[nodiscard]] auto find_member(canonicaljson::Object const& obj, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& m : obj)
        {
            if (m.key == key)
            {
                return m.value.get();
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto as_object(canonicaljson::Value const& v) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&v.storage());
    }

    [[nodiscard]] auto as_string(canonicaljson::Value const& v) noexcept -> std::string const*
    {
        return std::get_if<std::string>(&v.storage());
    }

    [[nodiscard]] auto as_bool(canonicaljson::Value const& v) noexcept -> bool const*
    {
        return std::get_if<bool>(&v.storage());
    }

    [[nodiscard]] auto as_int(canonicaljson::Value const& v) noexcept -> std::int64_t const*
    {
        return std::get_if<std::int64_t>(&v.storage());
    }

    [[nodiscard]] auto as_array(canonicaljson::Value const& v) noexcept -> canonicaljson::Array const*
    {
        return std::get_if<canonicaljson::Array>(&v.storage());
    }

    [[nodiscard]] auto extract_strings(canonicaljson::Value const& v) -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        auto const* arr = as_array(v);
        if (arr == nullptr)
        {
            return out;
        }
        for (auto const& item : *arr)
        {
            if (auto const* s = as_string(item); s != nullptr)
            {
                out.push_back(*s);
            }
        }
        return out;
    }

    // ── Sub-parsers ──────────────────────────────────────────────────────────

    [[nodiscard]] auto parse_range(canonicaljson::Value const& v) -> std::optional<SlidingSyncRange>
    {
        auto const* arr = as_array(v);
        if (arr == nullptr || arr->size() < 2U)
        {
            return std::nullopt;
        }
        auto const* start = as_int((*arr)[0]);
        auto const* end = as_int((*arr)[1]);
        if (start == nullptr || end == nullptr || *start < 0 || *end < 0)
        {
            return std::nullopt;
        }
        return SlidingSyncRange{static_cast<std::uint64_t>(*start), static_cast<std::uint64_t>(*end)};
    }

    [[nodiscard]] auto parse_ranges(canonicaljson::Value const& v) -> std::optional<std::vector<SlidingSyncRange>>
    {
        auto const* arr = as_array(v);
        if (arr == nullptr)
        {
            return std::nullopt;
        }
        auto out = std::vector<SlidingSyncRange>{};
        out.reserve(arr->size());
        for (auto const& item : *arr)
        {
            auto r = parse_range(item);
            if (!r.has_value())
            {
                return std::nullopt;
            }
            out.push_back(*r);
        }
        return out;
    }

    // Parse [[type, state_key], ...] required_state arrays.
    [[nodiscard]] auto parse_required_state(canonicaljson::Value const& v)
        -> std::vector<std::pair<std::string, std::string>>
    {
        auto out = std::vector<std::pair<std::string, std::string>>{};
        auto const* arr = as_array(v);
        if (arr == nullptr)
        {
            return out;
        }
        for (auto const& item : *arr)
        {
            auto const* pair_arr = as_array(item);
            if (pair_arr == nullptr || pair_arr->size() < 2U)
            {
                continue;
            }
            auto const* type = as_string((*pair_arr)[0]);
            auto const* state_key = as_string((*pair_arr)[1]);
            if (type == nullptr || state_key == nullptr)
            {
                continue;
            }
            out.emplace_back(*type, *state_key);
        }
        return out;
    }

    [[nodiscard]] auto parse_filters(canonicaljson::Object const& obj) -> SlidingSyncFilters
    {
        auto f = SlidingSyncFilters{};
        if (auto const* v = find_member(obj, "is_encrypted"); v != nullptr)
        {
            if (auto const* b = as_bool(*v); b != nullptr)
            {
                f.is_encrypted = *b;
            }
        }
        if (auto const* v = find_member(obj, "is_invite"); v != nullptr)
        {
            if (auto const* b = as_bool(*v); b != nullptr)
            {
                f.is_invite = *b;
            }
        }
        if (auto const* v = find_member(obj, "is_dm"); v != nullptr)
        {
            if (auto const* b = as_bool(*v); b != nullptr)
            {
                f.is_dm = *b;
            }
        }
        if (auto const* v = find_member(obj, "is_favourite"); v != nullptr)
        {
            if (auto const* b = as_bool(*v); b != nullptr)
            {
                f.is_favourite = *b;
            }
        }
        if (auto const* v = find_member(obj, "room_types"); v != nullptr)
        {
            f.room_types = extract_strings(*v);
        }
        if (auto const* v = find_member(obj, "not_room_types"); v != nullptr)
        {
            f.not_room_types = extract_strings(*v);
        }
        return f;
    }

    // Returns nullopt if ranges are invalid (overlapping).
    [[nodiscard]] auto parse_list(canonicaljson::Object const& obj) -> std::optional<SlidingSyncList>
    {
        auto list = SlidingSyncList{};

        if (auto const* v = find_member(obj, "ranges"); v != nullptr)
        {
            auto ranges = parse_ranges(*v);
            if (!ranges.has_value())
            {
                return std::nullopt;
            }
            if (!sliding_sync_ranges_valid(*ranges))
            {
                return std::nullopt;
            }
            list.ranges = std::move(*ranges);
        }

        if (auto const* v = find_member(obj, "sort"); v != nullptr)
        {
            list.sort = extract_strings(*v);
        }

        if (auto const* v = find_member(obj, "required_state"); v != nullptr)
        {
            list.required_state = parse_required_state(*v);
        }

        if (auto const* v = find_member(obj, "timeline_limit"); v != nullptr)
        {
            if (auto const* n = as_int(*v); n != nullptr && *n >= 0)
            {
                list.timeline_limit = static_cast<std::uint64_t>(*n);
            }
        }

        if (auto const* v = find_member(obj, "filters"); v != nullptr)
        {
            if (auto const* o = as_object(*v); o != nullptr)
            {
                list.filters = parse_filters(*o);
            }
        }

        if (auto const* v = find_member(obj, "include_heroes"); v != nullptr)
        {
            if (auto const* b = as_bool(*v); b != nullptr)
            {
                list.include_heroes = *b;
            }
        }

        if (auto const* v = find_member(obj, "bump_event_types"); v != nullptr)
        {
            list.bump_event_types = extract_strings(*v);
        }

        return list;
    }

    [[nodiscard]] auto parse_room_subscription(canonicaljson::Object const& obj) -> SlidingSyncRoomSubscription
    {
        auto sub = SlidingSyncRoomSubscription{};

        if (auto const* v = find_member(obj, "required_state"); v != nullptr)
        {
            sub.required_state = parse_required_state(*v);
        }
        if (auto const* v = find_member(obj, "timeline_limit"); v != nullptr)
        {
            if (auto const* n = as_int(*v); n != nullptr && *n >= 0)
            {
                sub.timeline_limit = static_cast<std::uint64_t>(*n);
            }
        }
        if (auto const* v = find_member(obj, "include_heroes"); v != nullptr)
        {
            if (auto const* b = as_bool(*v); b != nullptr)
            {
                sub.include_heroes = *b;
            }
        }
        return sub;
    }

    [[nodiscard]] auto parse_extension_requests(canonicaljson::Object const& obj) -> SlidingSyncExtensionRequests
    {
        auto ext = SlidingSyncExtensionRequests{};

        auto parse_enabled = [&](canonicaljson::Object const& o) -> bool {
            auto const* v = find_member(o, "enabled");
            if (v == nullptr)
            {
                return false;
            }
            auto const* b = as_bool(*v);
            return b != nullptr && *b;
        };

        if (auto const* v = find_member(obj, "to_device"); v != nullptr)
        {
            if (auto const* o = as_object(*v); o != nullptr)
            {
                auto req = ExtToDeviceRequest{};
                req.enabled = parse_enabled(*o);
                if (auto const* lv = find_member(*o, "limit"); lv != nullptr)
                {
                    if (auto const* n = as_int(*lv); n != nullptr && *n > 0)
                    {
                        req.limit = static_cast<std::uint64_t>(*n);
                    }
                }
                if (auto const* sv = find_member(*o, "since"); sv != nullptr)
                {
                    if (auto const* s = as_string(*sv); s != nullptr)
                    {
                        req.since = *s;
                    }
                }
                ext.to_device = req;
            }
        }

        if (auto const* v = find_member(obj, "e2ee"); v != nullptr)
        {
            if (auto const* o = as_object(*v); o != nullptr)
            {
                ext.e2ee = ExtE2eeRequest{parse_enabled(*o)};
            }
        }

        if (auto const* v = find_member(obj, "account_data"); v != nullptr)
        {
            if (auto const* o = as_object(*v); o != nullptr)
            {
                ext.account_data = ExtAccountDataRequest{parse_enabled(*o)};
            }
        }

        if (auto const* v = find_member(obj, "receipts"); v != nullptr)
        {
            if (auto const* o = as_object(*v); o != nullptr)
            {
                auto req = ExtReceiptsRequest{};
                req.enabled = parse_enabled(*o);
                if (auto const* rv = find_member(*o, "rooms"); rv != nullptr)
                {
                    req.rooms = extract_strings(*rv);
                }
                ext.receipts = req;
            }
        }

        if (auto const* v = find_member(obj, "typing"); v != nullptr)
        {
            if (auto const* o = as_object(*v); o != nullptr)
            {
                auto req = ExtTypingRequest{};
                req.enabled = parse_enabled(*o);
                if (auto const* rv = find_member(*o, "rooms"); rv != nullptr)
                {
                    req.rooms = extract_strings(*rv);
                }
                ext.typing = req;
            }
        }

        return ext;
    }

    // Extract a single named query parameter value from a target string like
    // "/_matrix/.../sync?pos=abc&timeout=30000".
    [[nodiscard]] auto qparam(std::string_view target, std::string_view name) -> std::string
    {
        auto const q = target.find('?');
        if (q == std::string_view::npos)
        {
            return {};
        }
        auto query = target.substr(q + 1U);
        while (!query.empty())
        {
            auto const amp = query.find('&');
            auto const pair = query.substr(0U, amp);
            auto const eq = pair.find('=');
            if (eq != std::string_view::npos)
            {
                auto const key = pair.substr(0U, eq);
                if (key == name)
                {
                    return core::percent_decode(pair.substr(eq + 1U));
                }
            }
            if (amp == std::string_view::npos)
            {
                break;
            }
            query = query.substr(amp + 1U);
        }
        return {};
    }

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

auto parse_sliding_sync_request(std::string_view body) -> std::optional<SlidingSyncRequest>
{
    if (body.empty())
    {
        // An empty body is valid — treated as an empty request.
        return SlidingSyncRequest{};
    }

    auto const parsed = canonicaljson::parse_lossless(body);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* root = as_object(parsed.value);
    if (root == nullptr)
    {
        return std::nullopt;
    }

    auto req = SlidingSyncRequest{};

    if (auto const* v = find_member(*root, "conn_id"); v != nullptr)
    {
        if (auto const* s = as_string(*v); s != nullptr)
        {
            req.conn_id = *s;
        }
    }

    if (auto const* v = find_member(*root, "lists"); v != nullptr)
    {
        auto const* lists_obj = as_object(*v);
        if (lists_obj == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& member : *lists_obj)
        {
            auto const* list_obj = as_object(*member.value);
            if (list_obj == nullptr)
            {
                return std::nullopt;
            }
            auto list = parse_list(*list_obj);
            if (!list.has_value())
            {
                return std::nullopt; // invalid ranges or malformed list
            }
            req.lists.emplace(member.key, std::move(*list));
        }
    }

    if (auto const* v = find_member(*root, "room_subscriptions"); v != nullptr)
    {
        auto const* subs_obj = as_object(*v);
        if (subs_obj != nullptr)
        {
            for (auto const& member : *subs_obj)
            {
                auto const* sub_obj = as_object(*member.value);
                if (sub_obj == nullptr)
                {
                    continue;
                }
                req.room_subscriptions.emplace(member.key, parse_room_subscription(*sub_obj));
            }
        }
    }

    if (auto const* v = find_member(*root, "extensions"); v != nullptr)
    {
        if (auto const* o = as_object(*v); o != nullptr)
        {
            req.extensions = parse_extension_requests(*o);
        }
    }

    return req;
}

auto parse_sliding_sync_pos(std::string_view target) -> std::optional<StreamToken>
{
    auto const raw = qparam(target, "pos");
    if (raw.empty())
    {
        return std::nullopt;
    }
    return decode_stream_token(raw);
}

auto parse_sliding_sync_timeout(std::string_view target) -> std::optional<std::uint64_t>
{
    auto const raw = qparam(target, "timeout");
    if (raw.empty())
    {
        return std::nullopt;
    }
    auto value = std::uint64_t{0U};
    for (auto const ch : raw)
    {
        if (ch < '0' || ch > '9')
        {
            return std::nullopt;
        }
        value = value * 10U + static_cast<std::uint64_t>(ch - '0');
    }
    return value;
}

auto sliding_sync_ranges_valid(std::vector<SlidingSyncRange> const& ranges) noexcept -> bool
{
    // Each range must satisfy start <= end, and consecutive ranges must not overlap:
    // ranges[i].end must be strictly less than ranges[i+1].start.
    for (std::size_t i = 0U; i < ranges.size(); ++i)
    {
        if (ranges[i].start > ranges[i].end)
        {
            return false;
        }
        if (i + 1U < ranges.size() && ranges[i].end >= ranges[i + 1U].start)
        {
            return false;
        }
    }
    return true;
}

} // namespace merovingian::sync
