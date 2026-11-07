// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/RawNumber.hpp"

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace merovingian::canonicaljson
{

class Value;

using Array = std::vector<Value>;
using Object = std::vector<ObjectMember>;

class Value final
{
public:
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object, RawNumber>;

    Value() = default;
    explicit Value(std::nullptr_t value);
    explicit Value(bool value);
    explicit Value(std::int64_t value);
    explicit Value(double value);
    explicit Value(std::string value);
    explicit Value(Array value);
    explicit Value(Object value);
    explicit Value(RawNumber value);

    Value(Value&& other) noexcept = default;
    auto operator=(Value&& other) noexcept -> Value& = default;

    Value(Value const& other);
    auto operator=(Value const& other) -> Value&;

    [[nodiscard]] auto storage() const noexcept -> Storage const&;

private:
    Storage m_storage{nullptr};
};

[[nodiscard]] auto make_member(std::string key, Value value) -> ObjectMember;

} // namespace merovingian::canonicaljson
