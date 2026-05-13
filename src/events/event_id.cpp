// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/event_id.hpp"
#include "merovingian/canonicaljson/serializer.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::events
{
namespace
{

[[nodiscard]] auto fnv1a64(std::string_view input) noexcept -> std::uint64_t
{
    auto hash = std::uint64_t{14695981039346656037ULL};
    for (auto const character : input)
    {
        hash ^= static_cast<unsigned char>(character);
        hash *= 1099511628211ULL;
    }
    return hash;
}

[[nodiscard]] auto hex_digit(std::uint8_t value) noexcept -> char
{
    constexpr auto digits = "0123456789abcdef";
    return digits[value & 0x0FU];
}

[[nodiscard]] auto to_hex(std::uint64_t value) -> std::string
{
    auto output = std::string(16U, '0');
    for (auto index = std::size_t{0U}; index < output.size(); ++index)
    {
        auto const shift = static_cast<unsigned int>((output.size() - index - 1U) * 4U);
        output[index] = hex_digit(static_cast<std::uint8_t>((value >> shift) & 0x0FU));
    }
    return output;
}

} // namespace

auto event_id_is_valid(std::string_view event_id) noexcept -> bool
{
    if (event_id.size() < 3U || event_id.front() != '$')
    {
        return false;
    }

    for (auto const character : event_id.substr(1U))
    {
        auto const valid = (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
            || (character >= '0' && character <= '9') || character == '_' || character == '-' || character == ':'
            || character == '.';
        if (!valid)
        {
            return false;
        }
    }

    return true;
}

auto make_content_hash_id(canonicaljson::Value const& event) -> EventIdResult
{
    auto const serialized = canonicaljson::serialize_canonical(event);
    if (serialized.error != canonicaljson::CanonicalJsonError::none)
    {
        return {{}, canonicaljson::canonical_json_error_name(serialized.error)};
    }

    return {"$" + to_hex(fnv1a64(serialized.output)), {}};
}

} // namespace merovingian::events
