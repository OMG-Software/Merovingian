// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/value.hpp"

#include <memory>
#include <utility>

namespace merovingian::canonicaljson
{
namespace
{

    // Canonical JSON values are trees; object cloning recursively deep-copies children.
    // NOLINTNEXTLINE(misc-no-recursion)
    [[nodiscard]] auto clone_object(Object const& object) -> Object
    {
        auto cloned = Object{};
        cloned.reserve(object.size());
        for (auto const& member : object)
        {
            cloned.push_back(make_member(member.key, *member.value));
        }

        return cloned;
    }

} // namespace

Value::Value(std::nullptr_t value)
    : m_storage{value}
{
}

Value::Value(bool value)
    : m_storage{value}
{
}

Value::Value(std::int64_t value)
    : m_storage{value}
{
}

Value::Value(double value)
    : m_storage{value}
{
}

Value::Value(std::string value)
    : m_storage{std::move(value)}
{
}

Value::Value(Array value)
    : m_storage{std::move(value)}
{
}

Value::Value(Object value)
    : m_storage{std::move(value)}
{
}

Value::Value(RawNumber value)
    : m_storage{std::move(value)}
{
}

// Canonical JSON values are recursive trees, so copying deep-copies nested values.
// NOLINTNEXTLINE(misc-no-recursion)
Value::Value(Value const& other)
{
    *this = other;
}

// Canonical JSON values are recursive trees, so copying deep-copies nested values.
// NOLINTNEXTLINE(misc-no-recursion)
auto Value::operator=(Value const& other) -> Value&
{
    if (this == &other)
    {
        return *this;
    }

    if (auto const* object = std::get_if<Object>(&other.m_storage); object != nullptr)
    {
        m_storage = clone_object(*object);
    }
    else
    {
        m_storage = other.m_storage;
    }

    return *this;
}

auto Value::storage() const noexcept -> Storage const&
{
    return m_storage;
}

auto make_member(std::string key, Value value) -> ObjectMember
{
    return {std::move(key), std::make_unique<Value>(std::move(value))};
}

} // namespace merovingian::canonicaljson
