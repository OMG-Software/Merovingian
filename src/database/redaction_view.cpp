// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/redaction_view.hpp"

#include "merovingian/canonicaljson/parser.hpp"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace merovingian::database
{
namespace
{

    [[nodiscard]] auto find_member(canonicaljson::Object& object, std::string_view key) noexcept
        -> canonicaljson::ObjectMember*
    {
        for (auto& member : object)
        {
            if (member.key == key)
            {
                return &member;
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return std::get_if<std::string>(&member.value->storage());
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto object_member(canonicaljson::Object& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* member = find_member(object, key);
        return member == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&member->value->storage());
    }

    // Replaces the value of `key`, or adds the member. Values are immutable once built, so a changed
    // object is rebuilt and put in place of the old one.
    auto set_member(canonicaljson::Object& object, std::string_view key, canonicaljson::Value value) -> void
    {
        if (auto* member = find_member(object, key); member != nullptr)
        {
            member->value = std::make_unique<canonicaljson::Value>(std::move(value));
            return;
        }
        object.push_back(canonicaljson::make_member(std::string{key}, std::move(value)));
    }

} // namespace

auto add_redaction_compat(canonicaljson::Object& client_event) -> void
{
    auto const* type = string_member(client_event, "type");
    if (type == nullptr || *type != "m.room.redaction")
    {
        return;
    }
    auto const* content = object_member(client_event, "content");
    auto const* top_level = string_member(client_event, "redacts");
    auto const* in_content = content == nullptr ? nullptr : string_member(*content, "redacts");
    if (top_level != nullptr && in_content == nullptr && content != nullptr)
    {
        auto widened = *content;
        widened.push_back(canonicaljson::make_member("redacts", canonicaljson::Value{*top_level}));
        set_member(client_event, "content", canonicaljson::Value{std::move(widened)});
    }
    else if (in_content != nullptr && top_level == nullptr)
    {
        client_event.push_back(canonicaljson::make_member("redacts", canonicaljson::Value{*in_content}));
    }
}

auto attach_redacted_because(PersistentStore const& store, std::string_view event_id,
                             canonicaljson::Object& client_event) -> void
{
    auto const redaction_id = applied_redaction_of(store, event_id);
    if (!redaction_id.has_value())
    {
        return;
    }
    auto const redaction = std::ranges::find_if(store.events, [&redaction_id](PersistentEvent const& event) {
        return event.event_id == *redaction_id;
    });
    if (redaction == store.events.end())
    {
        return;
    }
    auto const parsed = canonicaljson::parse_lossless(redaction->json);
    auto const* stored = parsed.error == canonicaljson::ParseError::none
                             ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                             : nullptr;
    if (stored == nullptr)
    {
        return;
    }
    auto because = *stored;
    std::erase_if(because, [](canonicaljson::ObjectMember const& member) {
        return member.key == "event_id" || member.key == "unsigned";
    });
    because.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{*redaction_id}));
    add_redaction_compat(because);

    auto unsigned_object = canonicaljson::Object{};
    if (auto const* current = object_member(client_event, "unsigned"); current != nullptr)
    {
        for (auto const& member : *current)
        {
            if (member.key != "redacted_because")
            {
                unsigned_object.push_back(member);
            }
        }
    }
    unsigned_object.push_back(canonicaljson::make_member("redacted_because", canonicaljson::Value{std::move(because)}));
    set_member(client_event, "unsigned", canonicaljson::Value{std::move(unsigned_object)});
}

} // namespace merovingian::database
