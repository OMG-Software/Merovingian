// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/read_markers.hpp"

#include "merovingian/canonicaljson/parser.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace merovingian::sync
{

namespace
{

    // Spec (Client-Server API, "Threaded read receipts"): "a maximum of 3 hops is recommended to
    // cover indirect relationships".
    constexpr auto max_thread_relation_hops = std::size_t{3U};

    [[nodiscard]] auto member_value(canonicaljson::Object const& object, std::string_view key) noexcept
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

    [[nodiscard]] auto member_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = member_value(object, key);
        return value != nullptr ? std::get_if<canonicaljson::Object>(&value->storage()) : nullptr;
    }

    [[nodiscard]] auto member_string(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = member_value(object, key);
        return value != nullptr ? std::get_if<std::string>(&value->storage()) : nullptr;
    }

    // The event's own relation: content."m.relates_to", or nullptr.
    [[nodiscard]] auto relation_of(canonicaljson::Object const& event) noexcept -> canonicaljson::Object const*
    {
        auto const* content = member_object(event, "content");
        return content != nullptr ? member_object(*content, "m.relates_to") : nullptr;
    }

} // namespace

auto ReadMarkers::covers(std::uint64_t stream_ordering, std::string_view thread_id) const noexcept -> bool
{
    if (stream_ordering <= unthreaded)
    {
        return true;
    }
    auto const thread = threads.find(thread_id);
    return thread != threads.end() && stream_ordering <= thread->second;
}

auto read_markers_for(std::vector<database::PersistentReceipt> const& receipts, database::PersistentStore const& store,
                      std::string_view room_id, std::string_view user) -> ReadMarkers
{
    // Spec: "Note that users can send both an m.read and m.read.private receipt, both of which are
    // capable of clearing notifications", and "the receipt which is more recent/ahead must be used".
    auto relevant = std::vector<database::PersistentReceipt const*>{};
    for (auto const& receipt : receipts)
    {
        if (receipt.room_id == room_id && receipt.user_id == user &&
            (receipt.receipt_type == "m.read" || receipt.receipt_type == "m.read.private"))
        {
            relevant.push_back(&receipt);
        }
    }

    auto markers = ReadMarkers{};
    if (!relevant.empty())
    {
        for (auto const& event : store.events)
        {
            if (event.room_id != room_id)
            {
                continue;
            }
            for (auto const* receipt : relevant)
            {
                if (receipt->event_id != event.event_id)
                {
                    continue;
                }
                auto& position = receipt->thread_id.empty() ? markers.unthreaded : markers.threads[receipt->thread_id];
                position = std::max(position, event.stream_ordering);
            }
        }
    }

    // Spec: "When the user updates their read receipt (either by using the API or by sending an
    // event), notifications prior to and including that event MUST be marked as read." An event
    // the user sends is in one thread, so it reads that thread up to itself (ADR-0170). Only
    // non-state events count: a state event can be sent for the user by this server without the
    // user looking at the room (a profile change is sent to every room as their m.room.member).
    // Events an unthreaded receipt already covers cannot move any position, so they are skipped.
    for (auto const& event : store.events)
    {
        if (event.room_id != room_id || event.sender_user_id != user || event.stream_ordering <= markers.unthreaded)
        {
            continue;
        }
        auto thread_id = std::string{main_thread_id};
        // Without either key the event is a non-state event in the main timeline; parse only when
        // the text could hold a state_key or a relation.
        if (event.json.find("\"state_key\"") != std::string::npos ||
            event.json.find("\"m.relates_to\"") != std::string::npos)
        {
            auto const parsed = canonicaljson::parse_lossless(event.json);
            auto const* object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (parsed.error != canonicaljson::ParseError::none || object == nullptr ||
                member_value(*object, "state_key") != nullptr)
            {
                continue;
            }
            thread_id = event_thread_id(store, *object);
        }
        auto& position = markers.threads[thread_id];
        position = std::max(position, event.stream_ordering);
    }
    return markers;
}

namespace
{

    // event_thread_id's walk with the parent lookup supplied: `find` answers nullopt when it gave up
    // (a bounded lookup out of budget), which ends the walk with nullopt; otherwise the stored event
    // with that ID, or nullptr when the store holds none.
    template <typename Find>
    [[nodiscard]] auto thread_of(canonicaljson::Object const& event, Find&& find) -> std::optional<std::string>
    {
        // Parents are parsed into `parent`, which owns the object `current` points into while it is
        // examined.
        auto parent = canonicaljson::Value{};
        auto const* current = &event;
        for (auto hop = std::size_t{0U};; ++hop)
        {
            auto const* relation = relation_of(*current);
            auto const* related_id = relation != nullptr ? member_string(*relation, "event_id") : nullptr;
            if (related_id == nullptr || related_id->empty())
            {
                return std::string{main_thread_id};
            }
            auto const* rel_type = member_string(*relation, "rel_type");
            if (rel_type != nullptr && *rel_type == "m.thread")
            {
                return *related_id;
            }
            if (hop == max_thread_relation_hops)
            {
                return std::string{main_thread_id};
            }
            auto const stored = find(*related_id);
            if (!stored.has_value())
            {
                return std::nullopt;
            }
            if (*stored == nullptr)
            {
                return std::string{main_thread_id};
            }
            auto parsed = canonicaljson::parse_lossless((*stored)->json);
            auto const* parent_object = std::get_if<canonicaljson::Object>(&parsed.value.storage());
            if (parsed.error != canonicaljson::ParseError::none || parent_object == nullptr)
            {
                return std::string{main_thread_id};
            }
            parent = std::move(parsed.value);
            current = std::get_if<canonicaljson::Object>(&parent.storage());
        }
    }

} // namespace

auto event_thread_id_within(database::PersistentStore const& store, canonicaljson::Object const& event,
                            std::uint64_t& rows_left) -> std::optional<std::string>
{
    return thread_of(
        event, [&store, &rows_left](std::string const& event_id) -> std::optional<database::PersistentEvent const*> {
            if (rows_left == 0U)
            {
                return std::nullopt;
            }
            --rows_left;
            auto const stored = store.events.find(event_id);
            return stored == store.events.end() ? nullptr : &*stored;
        });
}

auto event_thread_id(database::PersistentStore const& store, canonicaljson::Object const& event) -> std::string
{
    auto unlimited = std::numeric_limits<std::uint64_t>::max();
    return *event_thread_id_within(store, event, unlimited);
}

} // namespace merovingian::sync
