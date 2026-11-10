// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/UnsignedData.hpp"

#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"

#include <algorithm>
#include <utility>
#include <variant>

namespace merovingian::events
{

namespace
{

    [[nodiscard]] auto is_unsigned(canonicaljson::ObjectMember const& member) noexcept -> bool
    {
        return member.key == "unsigned";
    }

} // namespace

auto without_unsigned(canonicaljson::Value const& event) -> canonicaljson::Value
{
    auto const* object = std::get_if<canonicaljson::Object>(&event.storage());
    if (object == nullptr || !std::ranges::any_of(*object, is_unsigned))
    {
        return event;
    }
    auto kept = *object;
    std::erase_if(kept, is_unsigned);
    return canonicaljson::Value{std::move(kept)};
}

auto without_unsigned_json(std::string_view event_json) -> std::optional<std::string>
{
    // Cheap exit for the common case: a PDU that never names the key is not parsed again.
    if (event_json.find("\"unsigned\"") == std::string_view::npos)
    {
        return std::string{event_json};
    }
    auto const parsed = canonicaljson::parse_lossless(event_json);
    auto const* object = parsed.error == canonicaljson::ParseError::none
                             ? std::get_if<canonicaljson::Object>(&parsed.value.storage())
                             : nullptr;
    if (object == nullptr)
    {
        return std::nullopt;
    }
    if (!std::ranges::any_of(*object, is_unsigned))
    {
        return std::string{event_json};
    }
    auto const serialized = canonicaljson::serialize_canonical(without_unsigned(parsed.value));
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return std::nullopt;
    }
    return serialized.output;
}

} // namespace merovingian::events
