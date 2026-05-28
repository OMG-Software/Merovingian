// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::tests
{

[[nodiscard]] inline auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
    -> canonicaljson::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
            return member.value.get();
    }
    return nullptr;
}

[[nodiscard]] inline auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::string const*
{
    auto const* v = object_member(object, key);
    return v == nullptr ? nullptr : std::get_if<std::string>(&v->storage());
}

[[nodiscard]] inline auto bool_member(canonicaljson::Object const& object, std::string_view key) noexcept
    -> bool const*
{
    auto const* v = object_member(object, key);
    return v == nullptr ? nullptr : std::get_if<bool>(&v->storage());
}

[[nodiscard]] inline auto int_member(canonicaljson::Object const& object, std::string_view key) noexcept
    -> std::int64_t const*
{
    auto const* v = object_member(object, key);
    return v == nullptr ? nullptr : std::get_if<std::int64_t>(&v->storage());
}

[[nodiscard]] inline auto object_member_as_object(canonicaljson::Object const& object,
                                                   std::string_view key) noexcept
    -> canonicaljson::Object const*
{
    auto const* v = object_member(object, key);
    return v == nullptr ? nullptr : std::get_if<canonicaljson::Object>(&v->storage());
}

[[nodiscard]] inline auto object_member_as_array(canonicaljson::Object const& object,
                                                  std::string_view key) noexcept
    -> canonicaljson::Array const*
{
    auto const* v = object_member(object, key);
    return v == nullptr ? nullptr : std::get_if<canonicaljson::Array>(&v->storage());
}

[[nodiscard]] inline auto parse_object(std::string const& json) -> canonicaljson::Object
{
    auto const parsed = canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    auto const* obj = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(obj != nullptr);
    return *obj;
}

} // namespace merovingian::tests
