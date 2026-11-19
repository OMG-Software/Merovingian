// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/SlidingSyncParser.hpp"

#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/core/QueryParams.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
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

    // The strings of a JSON array, each kept once, in the order first seen. Used for the
    // extensions' room lists, where a repeated room ID asks for nothing more but would cost
    // another lookup under the runtime lock and count against the cap again.
    [[nodiscard]] auto extract_unique_strings(canonicaljson::Value const& v) -> std::vector<std::string>
    {
        auto out = std::vector<std::string>{};
        auto const* arr = as_array(v);
        if (arr == nullptr)
        {
            return out;
        }
        auto seen = std::set<std::string_view, std::less<>>{};
        for (auto const& item : *arr)
        {
            // The views point into the parsed document, which outlives this loop.
            if (auto const* s = as_string(item); s != nullptr && seen.insert(*s).second)
            {
                out.push_back(*s);
            }
        }
        return out;
    }

    // A client-supplied timeline_limit, reduced to the server maximum.
    [[nodiscard]] auto clamp_timeline_limit(std::int64_t requested, SlidingSyncLimits const& limits) noexcept
        -> std::uint64_t
    {
        return std::min(static_cast<std::uint64_t>(requested), static_cast<std::uint64_t>(limits.timeline_limit));
    }

    // What one string costs a stored copy: its object and its characters (ADR-0663).
    [[nodiscard]] auto string_cost(std::string const& s) noexcept -> std::uint64_t
    {
        return sizeof(std::string) + s.size();
    }

    [[nodiscard]] auto strings_cost(std::vector<std::string> const& strings) noexcept -> std::uint64_t
    {
        auto total = std::uint64_t{0U};
        for (auto const& s : strings)
        {
            total += string_cost(s);
        }
        return total;
    }

    [[nodiscard]] auto pairs_cost(std::vector<std::pair<std::string, std::string>> const& pairs) noexcept
        -> std::uint64_t
    {
        auto total = std::uint64_t{0U};
        for (auto const& [type, state_key] : pairs)
        {
            total += string_cost(type) + string_cost(state_key);
        }
        return total;
    }

    [[nodiscard]] auto configs_cost(std::vector<RequiredStateConfig> const& configs) noexcept -> std::uint64_t
    {
        auto total = std::uint64_t{0U};
        for (auto const& config : configs)
        {
            total += sizeof(RequiredStateConfig) + pairs_cost(config.include) + pairs_cost(config.exclude);
        }
        return total;
    }

    // The entries a room config's `required_state` names, in either form: each is matched against the room's state.
    template <typename RoomConfig>
    [[nodiscard]] auto required_state_entries(RoomConfig const& config) noexcept -> std::size_t
    {
        auto entries = config.required_state.size();
        for (auto const& request : config.required_state_configs)
        {
            entries += request.include.size() + request.exclude.size();
        }
        return entries;
    }

    // The appendices' "Opaque Identifiers" grammar, which MSC4186 requires of list keys: 1 to 255 of
    // [0-9A-Za-z-._~].
    [[nodiscard]] auto is_opaque_identifier(std::string_view id) noexcept -> bool
    {
        if (id.empty() || id.size() > 255U)
        {
            return false;
        }
        return std::ranges::all_of(id, [](char const c) {
            return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '.' ||
                   c == '_' || c == '~';
        });
    }

    // Per map node: the node links and the key string object, beside the list itself.
    constexpr auto list_node_overhead = std::uint64_t{64U};

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

    // A list's `room_types` or `not_room_types`: strings, and MSC4186's `null` for "rooms which do not have a room
    // type", held as the empty string, which is what a room with no type reads as. Anything else is skipped.
    [[nodiscard]] auto extract_room_types(canonicaljson::Value const& v) -> std::vector<std::string>
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
            else if (std::holds_alternative<std::nullptr_t>(item.storage()))
            {
                out.emplace_back();
            }
        }
        return out;
    }

    // One MSC4186 `RequiredStateElement`, as a [type, state_key] pair in which "*" stands for an omitted field. An
    // element that is not an object, or names a field that is not a string, matches nothing and is skipped.
    [[nodiscard]] auto parse_required_state_element(canonicaljson::Value const& v)
        -> std::optional<std::pair<std::string, std::string>>
    {
        auto const* obj = as_object(v);
        if (obj == nullptr)
        {
            return std::nullopt;
        }
        auto element = std::pair<std::string, std::string>{"*", "*"};
        if (auto const* type = find_member(*obj, "type"); type != nullptr)
        {
            auto const* s = as_string(*type);
            if (s == nullptr)
            {
                return std::nullopt;
            }
            element.first = *s;
        }
        if (auto const* state_key = find_member(*obj, "state_key"); state_key != nullptr)
        {
            auto const* s = as_string(*state_key);
            if (s == nullptr)
            {
                return std::nullopt;
            }
            element.second = *s;
        }
        return element;
    }

    [[nodiscard]] auto parse_required_state_elements(canonicaljson::Object const& request, std::string_view key)
        -> std::vector<std::pair<std::string, std::string>>
    {
        auto out = std::vector<std::pair<std::string, std::string>>{};
        auto const* v = find_member(request, key);
        auto const* arr = v != nullptr ? as_array(*v) : nullptr;
        if (arr == nullptr)
        {
            return out;
        }
        for (auto const& item : *arr)
        {
            if (auto element = parse_required_state_element(item); element.has_value())
            {
                out.push_back(std::move(*element));
            }
        }
        return out;
    }

    // MSC4186 "RequiredStateRequest": `{include, exclude, lazy_members}`.
    [[nodiscard]] auto parse_required_state_request(canonicaljson::Object const& request) -> RequiredStateConfig
    {
        auto config = RequiredStateConfig{};
        config.include = parse_required_state_elements(request, "include");
        config.exclude = parse_required_state_elements(request, "exclude");
        if (auto const* v = find_member(request, "lazy_members"); v != nullptr)
        {
            auto const* b = as_bool(*v);
            config.lazy_members = b != nullptr && *b;
        }
        return config;
    }

    // Parse [[type, state_key], ...] required_state arrays (the MSC3575 form).
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

    // A list's or subscription's `required_state`, in either form: the MSC4186 object or the MSC3575 array of pairs.
    template <typename RoomConfig>
    auto read_required_state(canonicaljson::Value const& v, RoomConfig& config) -> void
    {
        if (auto const* request = as_object(v); request != nullptr)
        {
            config.required_state_configs.push_back(parse_required_state_request(*request));
            return;
        }
        config.required_state = parse_required_state(v);
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
        // MSC4186 renamed `is_invite` to `is_invited`; a request that sends both is read from the new name.
        for (auto const* const key : {"is_invite", "is_invited"})
        {
            if (auto const* v = find_member(obj, key); v != nullptr)
            {
                if (auto const* b = as_bool(*v); b != nullptr)
                {
                    f.is_invite = *b;
                }
            }
        }
        if (auto const* v = find_member(obj, "spaces"); v != nullptr)
        {
            f.spaces = extract_unique_strings(*v);
        }
        if (auto const* v = find_member(obj, "tags"); v != nullptr)
        {
            f.tags = extract_unique_strings(*v);
        }
        if (auto const* v = find_member(obj, "not_tags"); v != nullptr)
        {
            f.not_tags = extract_unique_strings(*v);
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
            f.room_types = extract_room_types(*v);
        }
        if (auto const* v = find_member(obj, "not_room_types"); v != nullptr)
        {
            f.not_room_types = extract_room_types(*v);
        }
        return f;
    }

    // Returns nullopt if ranges are invalid (overlapping).
    [[nodiscard]] auto parse_list(canonicaljson::Object const& obj, SlidingSyncLimits const& limits)
        -> std::optional<SlidingSyncList>
    {
        auto list = SlidingSyncList{};

        // Newer MSC4186 / Element X uses the singular "range" key for a single
        // [start, end] window. Older clients (and the unstable prefix) use
        // the plural "ranges" array. Accept either; prefer "ranges" when both
        // are present so we do not accidentally duplicate a window.
        if (auto const* ranges_val = find_member(obj, "ranges"); ranges_val != nullptr)
        {
            auto ranges = parse_ranges(*ranges_val);
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
        else if (auto const* range_val = find_member(obj, "range"); range_val != nullptr)
        {
            auto const single = parse_range(*range_val);
            if (!single.has_value())
            {
                return std::nullopt;
            }
            if (!sliding_sync_ranges_valid(std::vector<SlidingSyncRange>{*single}))
            {
                return std::nullopt;
            }
            list.ranges.push_back(*single);
        }
        else
        {
            list.whole_list = true;
        }

        if (auto const* v = find_member(obj, "sort"); v != nullptr)
        {
            list.sort = extract_strings(*v);
        }

        if (auto const* v = find_member(obj, "required_state"); v != nullptr)
        {
            read_required_state(*v, list);
        }

        if (auto const* v = find_member(obj, "timeline_limit"); v != nullptr)
        {
            if (auto const* n = as_int(*v); n != nullptr && *n >= 0)
            {
                list.timeline_limit = clamp_timeline_limit(*n, limits);
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

    [[nodiscard]] auto parse_room_subscription(canonicaljson::Object const& obj, SlidingSyncLimits const& limits)
        -> SlidingSyncRoomSubscription
    {
        auto sub = SlidingSyncRoomSubscription{};

        if (auto const* v = find_member(obj, "required_state"); v != nullptr)
        {
            read_required_state(*v, sub);
        }
        if (auto const* v = find_member(obj, "timeline_limit"); v != nullptr)
        {
            if (auto const* n = as_int(*v); n != nullptr && *n >= 0)
            {
                sub.timeline_limit = clamp_timeline_limit(*n, limits);
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

    // MSC4508's scope keys, `lists` and `rooms`, of one room-scoped extension object (typing, receipts, sticky_events),
    // each de-duplicated. A key that is present but not an array of strings names nothing, as an empty array does.
    template <typename ScopedRequest>
    auto read_extension_scope(canonicaljson::Object const& source, ScopedRequest& request) -> void
    {
        if (auto const* v = find_member(source, "lists"); v != nullptr)
        {
            request.lists = extract_unique_strings(*v);
        }
        if (auto const* v = find_member(source, "rooms"); v != nullptr)
        {
            request.rooms = extract_unique_strings(*v);
        }
    }

    // Whether a scope key holds more than `cap` names; an absent key holds none.
    [[nodiscard]] auto exceeds(std::optional<std::vector<std::string>> const& key, std::size_t cap) noexcept -> bool
    {
        return key.has_value() && key->size() > cap;
    }

    // MSC4480's extension is sent under `sticky_events` or `org.matrix.msc4354.sticky_events`. A request that sends
    // both is one request, read from the stable name's object (ADR-0855), and is answered under both names.
    [[nodiscard]] auto parse_sticky_events_request(canonicaljson::Object const& extensions)
        -> std::optional<ExtStickyEventsRequest>
    {
        auto const* const stable = find_member(extensions, "sticky_events");
        auto const* const unstable = find_member(extensions, "org.matrix.msc4354.sticky_events");
        auto const* const stable_object = stable != nullptr ? as_object(*stable) : nullptr;
        auto const* const unstable_object = unstable != nullptr ? as_object(*unstable) : nullptr;
        if (stable_object == nullptr && unstable_object == nullptr)
        {
            return std::nullopt;
        }
        auto const& source = stable_object != nullptr ? *stable_object : *unstable_object;
        auto req = ExtStickyEventsRequest{};
        req.used_stable_name = stable_object != nullptr;
        req.used_unstable_name = unstable_object != nullptr;
        if (auto const* v = find_member(source, "enabled"); v != nullptr)
        {
            auto const* b = as_bool(*v);
            req.enabled = b != nullptr && *b;
        }
        if (auto const* v = find_member(source, "limit"); v != nullptr)
        {
            if (auto const* n = as_int(*v); n != nullptr)
            {
                if (*n < 1)
                {
                    req.limit_refused = true;
                }
                else
                {
                    req.limit = static_cast<std::uint32_t>(
                        std::min<std::int64_t>(*n, static_cast<std::int64_t>(max_sticky_events_per_room_response)));
                }
            }
        }
        read_extension_scope(source, req);
        return req;
    }

    // One extension's request object, read from its MSC-prefixed key when the request sent it and from its bare key
    // otherwise, with the keys the request used (ADR-0865). `object` is null when neither key holds an object.
    struct ExtensionObject final
    {
        canonicaljson::Object const* object{nullptr};
        ExtensionNames names{};
    };

    [[nodiscard]] auto extension_object(canonicaljson::Object const& extensions, std::string_view bare,
                                        std::string_view prefixed) -> ExtensionObject
    {
        auto const* const bare_value = find_member(extensions, bare);
        auto const* const prefixed_value = find_member(extensions, prefixed);
        auto const* const bare_object = bare_value != nullptr ? as_object(*bare_value) : nullptr;
        auto const* const prefixed_object = prefixed_value != nullptr ? as_object(*prefixed_value) : nullptr;
        auto found = ExtensionObject{};
        found.object = prefixed_object != nullptr ? prefixed_object : bare_object;
        found.names.bare = bare_object != nullptr;
        found.names.prefixed = prefixed_object != nullptr;
        return found;
    }

    [[nodiscard]] auto parse_enabled(canonicaljson::Object const& o) -> bool
    {
        auto const* v = find_member(o, "enabled");
        if (v == nullptr)
        {
            return false;
        }
        auto const* b = as_bool(*v);
        return b != nullptr && *b;
    }

    // MSC4538: "A `limit` that is not a positive integer ... MUST be rejected with a 400 and an error code of
    // `M_BAD_JSON`"; the handler answers `limit_refused`.
    [[nodiscard]] auto parse_to_device_request(canonicaljson::Object const& o, ExtensionNames names)
        -> ExtToDeviceRequest
    {
        auto req = ExtToDeviceRequest{};
        req.enabled = parse_enabled(o);
        req.names = names;
        if (auto const* lv = find_member(o, "limit"); lv != nullptr)
        {
            auto const* n = as_int(*lv);
            if (n == nullptr || *n <= 0)
            {
                req.limit_refused = true;
            }
            else
            {
                req.limit = static_cast<std::uint64_t>(*n);
            }
        }
        if (auto const* sv = find_member(o, "since"); sv != nullptr)
        {
            if (auto const* s = as_string(*sv); s != nullptr)
            {
                req.since = *s;
            }
        }
        return req;
    }

    template <typename ScopedRequest>
    [[nodiscard]] auto parse_scoped_request(canonicaljson::Object const& o, ExtensionNames names) -> ScopedRequest
    {
        auto req = ScopedRequest{};
        req.enabled = parse_enabled(o);
        req.names = names;
        read_extension_scope(o, req);
        return req;
    }

    [[nodiscard]] auto parse_extension_requests(canonicaljson::Object const& obj) -> SlidingSyncExtensionRequests
    {
        auto ext = SlidingSyncExtensionRequests{};

        if (auto const found = extension_object(obj, "to_device", "org.matrix.msc4538.to_device");
            found.object != nullptr)
        {
            ext.to_device = parse_to_device_request(*found.object, found.names);
        }
        if (auto const found = extension_object(obj, "e2ee", "org.matrix.msc4543.e2ee"); found.object != nullptr)
        {
            ext.e2ee = ExtE2eeRequest{parse_enabled(*found.object), found.names};
        }
        if (auto const found = extension_object(obj, "account_data", "org.matrix.msc4548.account_data");
            found.object != nullptr)
        {
            ext.account_data = parse_scoped_request<ExtAccountDataRequest>(*found.object, found.names);
        }
        if (auto const found = extension_object(obj, "receipts", "org.matrix.msc4551.receipts");
            found.object != nullptr)
        {
            ext.receipts = parse_scoped_request<ExtReceiptsRequest>(*found.object, found.names);
        }
        if (auto const found = extension_object(obj, "typing", "org.matrix.msc4508.typing"); found.object != nullptr)
        {
            ext.typing = parse_scoped_request<ExtTypingRequest>(*found.object, found.names);
        }

        ext.sticky_events = parse_sticky_events_request(obj);

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

    // The room-scoped extensions name rooms as room_subscriptions does and lists as `lists` does (MSC4508), and each
    // name costs a lookup under the runtime lock, so the same caps bound them.
    [[nodiscard]] auto extension_limit_violation(SlidingSyncExtensionRequests const& extensions,
                                                 SlidingSyncLimits const& limits) -> std::optional<std::string_view>
    {
        if (extensions.receipts.has_value())
        {
            if (exceeds(extensions.receipts->rooms, limits.room_subscriptions))
            {
                return "too many rooms in the receipts extension";
            }
            if (exceeds(extensions.receipts->lists, limits.lists))
            {
                return "too many lists in the receipts extension";
            }
        }
        if (extensions.typing.has_value())
        {
            if (exceeds(extensions.typing->rooms, limits.room_subscriptions))
            {
                return "too many rooms in the typing extension";
            }
            if (exceeds(extensions.typing->lists, limits.lists))
            {
                return "too many lists in the typing extension";
            }
        }
        if (extensions.account_data.has_value())
        {
            if (exceeds(extensions.account_data->rooms, limits.room_subscriptions))
            {
                return "too many rooms in the account_data extension";
            }
            if (exceeds(extensions.account_data->lists, limits.lists))
            {
                return "too many lists in the account_data extension";
            }
        }
        if (extensions.sticky_events.has_value())
        {
            if (extensions.sticky_events->limit_refused)
            {
                return "the sticky_events limit must be at least 1";
            }
            auto const& sticky = *extensions.sticky_events;
            if (exceeds(sticky.rooms, limits.room_subscriptions))
            {
                return "too many rooms in the sticky_events extension";
            }
            if (exceeds(sticky.lists, limits.lists))
            {
                return "too many lists in the sticky_events extension";
            }
        }
        return std::nullopt;
    }

} // namespace

// ── Public API ───────────────────────────────────────────────────────────────

auto parse_sliding_sync_request(std::string_view body, SlidingSyncLimits limits) -> std::optional<SlidingSyncRequest>
{
    if (body.empty())
    {
        // An empty body is valid — treated as an empty request.
        return SlidingSyncRequest{};
    }

    // The canonical parser refuses floats and exponents, so range bounds and timeouts arrive as exact integers or the
    // request fails here.
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

    // A field of the wrong type is ignored, except `lists`: a malformed list or range fails the whole request.
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
            // A list that is not an object is malformed, so reject the whole request.
            auto const* list_obj = as_object(*member.value);
            if (list_obj == nullptr)
            {
                return std::nullopt;
            }
            auto list = parse_list(*list_obj, limits);
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
                // Unlike lists, a malformed subscription is skipped so one bad room does not fail the request.
                auto const* sub_obj = as_object(*member.value);
                if (sub_obj == nullptr)
                {
                    continue;
                }
                req.room_subscriptions.emplace(member.key, parse_room_subscription(*sub_obj, limits));
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

    if (auto const* v = find_member(*root, "pos"); v != nullptr)
    {
        if (auto const* s = as_string(*v); s != nullptr)
        {
            req.pos = *s;
        }
    }

    if (auto const* v = find_member(*root, "timeout"); v != nullptr)
    {
        if (auto const* n = as_int(*v); n != nullptr && *n >= 0)
        {
            req.timeout = static_cast<std::uint64_t>(*n);
        }
    }

    if (auto const* v = find_member(*root, "set_presence"); v != nullptr)
    {
        auto const* s = as_string(*v);
        req.set_presence = s != nullptr ? *s : std::string{};
    }

    return req;
}

auto sliding_sync_retained_bytes(std::map<std::string, SlidingSyncList> const& lists) noexcept -> std::uint64_t
{
    auto total = std::uint64_t{0U};
    for (auto const& [name, list] : lists)
    {
        total += list_node_overhead + string_cost(name) + sizeof(SlidingSyncList);
        total += list.ranges.size() * sizeof(SlidingSyncRange);
        total += strings_cost(list.sort) + strings_cost(list.bump_event_types);
        total += pairs_cost(list.required_state) + configs_cost(list.required_state_configs);
        if (list.filters.has_value())
        {
            auto const& f = *list.filters;
            total += strings_cost(f.room_types) + strings_cost(f.not_room_types) + strings_cost(f.spaces) +
                     strings_cost(f.tags) + strings_cost(f.not_tags);
        }
    }
    return total;
}

auto sliding_sync_retained_bytes(SlidingSyncRequest const& request) noexcept -> std::uint64_t
{
    auto const conn_id = request.conn_id.has_value() ? string_cost(*request.conn_id) : std::uint64_t{0U};
    return conn_id + sliding_sync_retained_bytes(request.lists);
}

auto sliding_sync_request_limit_violation(SlidingSyncRequest const& request) -> std::optional<std::string_view>
{
    return sliding_sync_request_limit_violation(request, SlidingSyncLimits{});
}

auto sliding_sync_request_limit_violation(SlidingSyncRequest const& request, SlidingSyncLimits limits)
    -> std::optional<std::string_view>
{
    if (request.room_subscriptions.size() > limits.room_subscriptions)
    {
        return "too many room_subscriptions";
    }
    if (request.conn_id.has_value() && request.conn_id->size() > limits.name_bytes)
    {
        return "conn_id too long";
    }
    if (request.lists.size() > limits.lists)
    {
        return "too many lists";
    }
    for ([[maybe_unused]] auto const& [name, list] : request.lists)
    {
        if (name.size() > limits.name_bytes)
        {
            return "list name too long";
        }
        if (!is_opaque_identifier(name))
        {
            return "a list key must be an opaque identifier";
        }
        if (list.ranges.size() > limits.ranges)
        {
            return "too many ranges in a list";
        }
        if (list.filters.has_value())
        {
            if (list.filters->room_types.size() > limits.room_types)
            {
                return "too many room_types in a list";
            }
            if (list.filters->not_room_types.size() > limits.room_types)
            {
                return "too many not_room_types in a list";
            }
            // Each named space costs a walk of its m.space.child state, and each tag a comparison per room.
            auto const& f = *list.filters;
            if (f.spaces.size() > limits.room_types || f.tags.size() > limits.room_types ||
                f.not_tags.size() > limits.room_types)
            {
                return "too many spaces or tags in a list";
            }
        }
        if (required_state_entries(list) > limits.required_state_entries)
        {
            return "too many required_state entries in a list";
        }
        if (list.sort.size() > limits.sort_keys)
        {
            return "too many sort keys in a list";
        }
        if (list.bump_event_types.size() > limits.bump_event_types)
        {
            return "too many bump_event_types in a list";
        }
    }
    for ([[maybe_unused]] auto const& [room_id, subscription] : request.room_subscriptions)
    {
        if (required_state_entries(subscription) > limits.required_state_entries)
        {
            return "too many required_state entries in a room subscription";
        }
    }
    if (request.extensions.has_value())
    {
        if (auto const violation = extension_limit_violation(*request.extensions, limits); violation.has_value())
        {
            return violation;
        }
    }
    // The count caps bound the entries; this bounds what they weigh, since a string may be as long as the body.
    if (sliding_sync_retained_bytes(request) > limits.retained_bytes_per_connection)
    {
        return "the lists are too large to keep for a connection";
    }
    return std::nullopt;
}

auto sliding_sync_request_malformation(SlidingSyncRequest const& request) -> std::optional<std::string_view>
{
    if (request.extensions.has_value() && request.extensions->to_device.has_value() &&
        request.extensions->to_device->limit_refused)
    {
        return "the to_device limit must be a positive integer";
    }
    return std::nullopt;
}

auto parse_sliding_sync_pos(std::string_view target) -> std::optional<SlidingSyncPos>
{
    auto const raw = qparam(target, "pos");
    if (raw.empty())
    {
        return std::nullopt;
    }
    return decode_sliding_sync_pos(raw);
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
        auto const digit = static_cast<std::uint64_t>(ch - '0');
        auto constexpr maximum = std::numeric_limits<std::uint64_t>::max();
        value = value > (maximum - digit) / 10U ? maximum : value * 10U + digit;
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
