// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/ObjectMember.hpp"

#include "merovingian/canonicaljson/value.hpp"

#include <memory>
#include <string>
#include <utility>

namespace merovingian::canonicaljson
{

ObjectMember::ObjectMember(std::string key_value, std::unique_ptr<Value> owned_value)
    : key{std::move(key_value)}
    , value{std::move(owned_value)}
{
}

// Object members own child values, so copying intentionally deep-copies the child tree.
// NOLINTNEXTLINE(misc-no-recursion)
ObjectMember::ObjectMember(ObjectMember const& other)
    : key{other.key}
    , value{other.value == nullptr ? nullptr : std::make_unique<Value>(*other.value)}
{
}

// Object members own child values, so copying intentionally deep-copies the child tree.
// NOLINTNEXTLINE(misc-no-recursion)
auto ObjectMember::operator=(ObjectMember const& other) -> ObjectMember&
{
    if (this == &other)
    {
        return *this;
    }

    key = other.key;
    value = other.value == nullptr ? nullptr : std::make_unique<Value>(*other.value);
    return *this;
}

} // namespace merovingian::canonicaljson
